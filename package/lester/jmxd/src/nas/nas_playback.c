// SPDX-License-Identifier: GPL-2.0-or-later
/* Temporary, bounded playback sessions. No byte stream is carried over ubus. */
#define _GNU_SOURCE
#include "nas_playback.h"
#include "storage/storage_files.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define SESSION_COUNT 2
#ifndef NAS_PLAYBACK_IDLE_SECONDS
#define NAS_PLAYBACK_IDLE_SECONDS 120
#endif
#define CACHE_LIMIT (64LL * 1024 * 1024)
#define FORMAT_LIST "mov,matroska,webm,avi,ogg,mp3,wav,flac,aac,mpegts,mpeg,asf"
struct session {
    char id[33], folder[64], root[48], path[PATH_MAX], error[64];
    int parent, dir, source, mode, audio, subtitle;
    double position;
    pid_t pid;
    time_t seen, started;
    int finished, exit_code;
};
static struct session sessions[SESSION_COUNT];
static volatile sig_atomic_t cancelled;
static int encoder_available = -1;
static const char *str(struct json_object *o, const char *k) {
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, k, &v) && json_object_is_type(v, json_type_string)
               ? json_object_get_string(v) : "";
}
static void add(struct json_object *o, const char *k, const char *v) {
    json_object_object_add(o, k, json_object_new_string(v));
}
static struct json_object *error(const char *reason, int code, int *status) {
    struct json_object *o = json_object_new_object();
    add(o, "error", reason); *status = code; return o;
}
static int number(struct json_object *o, const char *key, double def, double *out) {
    struct json_object *v = NULL; *out = def;
    if (!json_object_object_get_ex(o, key, &v)) return 0;
    if (!json_object_is_type(v, json_type_int) && !json_object_is_type(v, json_type_double)) return -1;
    *out = json_object_get_double(v);
    return !isfinite(*out) ? -1 : 0;
}
static void signal_cancel(int sig) { (void)sig; cancelled = 1; }
static int output(int dir, const char *name) {
    return openat(dir, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
}
static struct json_object *read_json(int dir, const char *name) {
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    struct json_object *o = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size <= 262144
                               ? json_object_from_fd(fd) : NULL;
    if (fd >= 0) close(fd);
    return o;
}
static void write_json(int dir, const char *name, struct json_object *o) {
    int fd = output(dir, "result.tmp");
    if (fd >= 0) {
        if (!json_object_to_fd(fd, o, JSON_C_TO_STRING_PLAIN) && !fsync(fd))
            renameat(dir, "result.tmp", dir, name);
        close(fd); unlinkat(dir, "result.tmp", 0);
    }
}
static void child_error(struct session *s, const char *reason) {
    struct json_object *o = json_object_new_object(); add(o, "error", reason);
    write_json(s->dir, "error.json", o); json_object_put(o); _exit(1);
}
static int run(char *const argv[], int input, int out, int log, int seconds) {
    pid_t parent = getpid(), pid = fork();
    if (!pid) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (getppid() != parent) _exit(1);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
        if (input >= 0) fcntl(input, F_SETFD, 0);
        dup2(out, STDOUT_FILENO); dup2(log, STDERR_FILENO);
        int null = open("/dev/null", O_RDONLY);
        if (null >= 0) { dup2(null, STDIN_FILENO); if (null > 2) close(null); }
        struct rlimit limit = {CACHE_LIMIT, CACHE_LIMIT}; setrlimit(RLIMIT_FSIZE, &limit);
        execv(argv[0], argv); _exit(127);
    }
    if (pid < 0) return -1;
    time_t start = time(NULL); int status = 0; struct timespec delay = {0, 20000000};
    for (;;) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) return WIFEXITED(status) && !WEXITSTATUS(status) ? 0 : -1;
        if (done < 0 && errno != EINTR) return -1;
        if (cancelled || (seconds && time(NULL) - start > seconds)) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        nanosleep(&delay, NULL);
    }
}
static char *read_text(int fd) {
    struct stat st;
    if (fstat(fd, &st) || st.st_size > 262144 || st.st_size < 0) return NULL;
    char *s = calloc((size_t)st.st_size + 1, 1);
    if (!s) return NULL;
    if (pread(fd, s, (size_t)st.st_size, 0) != st.st_size) { free(s); return NULL; }
    return s;
}
static int text_subtitle(const char *codec) {
    return !strcmp(codec, "subrip") || !strcmp(codec, "ass") || !strcmp(codec, "ssa") ||
           !strcmp(codec, "webvtt") || !strcmp(codec, "mov_text") || !strcmp(codec, "text");
}
static char *encoded(const char *text) {
    static const char hex[] = "0123456789ABCDEF";
    char *out = malloc(strlen(text) * 3 + 1), *p = out;
    if (!out) return NULL;
    for (const unsigned char *s = (const unsigned char *)text; *s; s++) {
        if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
            (*s >= '0' && *s <= '9') || *s == '-' || *s == '_' || *s == '.' || *s == '~') *p++ = *s;
        else { *p++ = '%'; *p++ = hex[*s >> 4]; *p++ = hex[*s & 15]; }
    }
    *p = 0; return out;
}
static double vtt_time(const char *s) {
    unsigned int a, b; double c; char tail;
    if (sscanf(s, "%u:%u:%lf%c", &a, &b, &c, &tail) == 3) return a * 3600.0 + b * 60.0 + c;
    if (sscanf(s, "%u:%lf%c", &a, &c, &tail) == 2) return a * 60.0 + c;
    return -1;
}
static void timestamp(FILE *out, double value) {
    long ms = (long)(value * 1000 + .5);
    fprintf(out, "%02ld:%02ld:%02ld.%03ld", ms / 3600000, ms / 60000 % 60, ms / 1000 % 60, ms % 1000);
}
static int retime_subtitles(struct session *s, int input) {
    /* FFmpeg's subtitle muxer can retain original packet timestamps across -ss.
     * Convert the complete text track, then shift/clamp the generated VTT cues
     * explicitly so its clock matches this HLS session's zero-based clock. */
    lseek(input, 0, SEEK_SET);
    FILE *in = fdopen(dup(input), "r"); int fd = output(s->dir, "subtitle.vtt");
    FILE *out = fd >= 0 ? fdopen(fd, "w") : NULL;
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); else if (fd >= 0) close(fd); return -1; }
    fputs("WEBVTT\n\n", out); char *line = NULL; size_t capacity = 0; int keep = 0;
    while (getline(&line, &capacity, in) > 0) {
        char from[64], to[64];
        if (sscanf(line, "%63s --> %63s", from, to) == 2) {
            double start = vtt_time(from) - s->position, end = vtt_time(to) - s->position;
            keep = end > 0 && end > start;
            if (keep) { timestamp(out, start > 0 ? start : 0); fputs(" --> ", out); timestamp(out, end); fputc('\n', out); }
        } else if (!strcmp(line, "\n") || !strcmp(line, "\r\n")) {
            if (keep) fputc('\n', out);
            keep = 0;
        } else if (keep) fputs(line, out);
    }
    free(line); int failed = ferror(in) || ferror(out); fclose(in);
    if (fclose(out)) failed = 1;
    return failed ? -1 : 0;
}
static void child(struct session *s) {
    pid_t parent = getppid();
    setpgid(0, 0); prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() != parent || parent == 1) _exit(1);
    signal(SIGTERM, signal_cancel); signal(SIGINT, signal_cancel); cancelled = 0;
    if (fchdir(s->dir)) _exit(1);
    int log = output(s->dir, "worker.log"), probe = output(s->dir, "probe.tmp");
    if (log < 0 || probe < 0) child_error(s, "cache_unwritable");
    char input[64]; snprintf(input, sizeof(input), "/proc/self/fd/%d", s->source);
    char *probe_args[] = {"/usr/bin/ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe",
        "-format_whitelist", FORMAT_LIST, "-show_entries",
        "format=duration,format_name:format_tags=title,artist,album:stream=index,codec_type,codec_name,width,height:stream_tags=language,title",
        "-of", "json", input, NULL};
    if (run(probe_args, s->source, probe, log, 15)) child_error(s, "probe_failed");
    lseek(probe, 0, SEEK_SET); struct json_object *meta = json_object_from_fd(probe), *streams = NULL, *format = NULL;
    close(probe); unlinkat(s->dir, "probe.tmp", 0);
    if (!meta || !json_object_object_get_ex(meta, "streams", &streams) ||
        !json_object_is_type(streams, json_type_array)) child_error(s, "probe_failed");
    json_object_object_get_ex(meta, "format", &format);
    double duration = atof(str(format, "duration"));
    if (s->position > 0 && (!isfinite(duration) || duration <= s->position)) child_error(s, "seek_out_of_range");
    int video = -1, audio = -1, subtitle = -1;
    for (size_t i = 0; i < json_object_array_length(streams); i++) {
        struct json_object *stream = json_object_array_get_idx(streams, i), *v = NULL;
        json_object_object_get_ex(stream, "index", &v); int index = json_object_get_int(v);
        if (!strcmp(str(stream, "codec_type"), "video") && video < 0) video = index;
        if (!strcmp(str(stream, "codec_type"), "audio") && (s->audio == index || (s->audio < 0 && audio < 0))) audio = index;
        if (!strcmp(str(stream, "codec_type"), "subtitle")) {
            int supported = text_subtitle(str(stream, "codec_name"));
            json_object_object_add(stream, "selectable", json_object_new_boolean(supported));
            if (!supported) add(stream, "reason", "image_subtitle_unsupported");
            if (s->subtitle == index && supported) subtitle = index;
        }
    }
    if ((s->audio >= 0 && audio != s->audio) || (s->subtitle >= 0 && subtitle != s->subtitle))
        child_error(s, "track_unsupported");
    int enc = output(s->dir, "encoders.tmp"), available = 0;
    if (enc >= 0 && !access("/usr/bin/ffmpeg", X_OK)) {
        char *args[] = {"/usr/bin/ffmpeg", "-hide_banner", "-encoders", NULL};
        if (!run(args, -1, enc, log, 10)) {
            char *text = read_text(enc);
            available = text && strstr(text, " libx264 ") && strstr(text, " aac ");
            free(text);
        }
    }
    if (enc >= 0) close(enc);
    unlinkat(s->dir, "encoders.tmp", 0);
    json_object_object_add(meta, "hls_available", json_object_new_boolean(available));
    if (!available) add(meta, "hls_reason", "encoder_missing");
    json_object_object_add(meta, "audio_index", json_object_new_int(audio));
    write_json(s->dir, "info.json", meta); json_object_put(meta);
    if (!s->mode) _exit(0);
    if (!available) child_error(s, "encoder_missing");
    if (video < 0 && audio < 0) child_error(s, "no_media_stream");
    char pos[40], amap[40], vmap[40], smap[40];
    snprintf(pos, sizeof(pos), "%.3f", s->position);
    snprintf(amap, sizeof(amap), "0:%d", audio);
    snprintf(vmap, sizeof(vmap), "0:%d", video);
    snprintf(smap, sizeof(smap), "0:%d", subtitle);
    if (subtitle >= 0) {
        lseek(s->source, 0, SEEK_SET);
        int out = output(s->dir, "subtitle.tmp");
        char *args[] = {"/usr/bin/ffmpeg", "-nostdin", "-v", "error", "-protocol_whitelist", "file,pipe",
            "-format_whitelist", FORMAT_LIST, "-copyts", "-i", input, "-map", smap,
            "-c:s", "webvtt", "-f", "webvtt", "pipe:1", NULL};
        if (out < 0 || run(args, s->source, out, log, 20)) child_error(s, "subtitle_failed");
        if (retime_subtitles(s, out)) child_error(s, "subtitle_failed");
        close(out); unlinkat(s->dir, "subtitle.tmp", 0);
    }
    lseek(s->source, 0, SEEK_SET);
    char prefix[PATH_MAX + 100];
    if (snprintf(prefix, sizeof(prefix), "%s/.dreamingos-nas/%s/", s->path, s->folder) >= (int)sizeof(prefix))
        child_error(s, "path_too_long");
    char *path = encoded(prefix), *root = encoded(s->root), *base = NULL;
    if (!path || !root || asprintf(&base, "/api/v1/storage/files/raw?root_id=%s&path=%s", root, path) < 0)
        child_error(s, "out_of_memory");
    free(path); free(root);
    char *args[100]; int n = 0;
#define ARG(v) args[n++] = (char *)(v)
    ARG("/usr/bin/ffmpeg"); ARG("-nostdin"); ARG("-v"); ARG("error");
    ARG("-protocol_whitelist"); ARG("file,pipe"); ARG("-format_whitelist"); ARG(FORMAT_LIST);
    ARG("-threads"); ARG("1"); ARG("-filter_threads"); ARG("1");
    ARG("-re"); ARG("-ss"); ARG(pos); ARG("-i"); ARG(input);
    if (video >= 0) {
        ARG("-map"); ARG(vmap); ARG("-c:v"); ARG("libx264"); ARG("-preset"); ARG("veryfast");
        ARG("-vf"); ARG("scale=w='min(1280,iw)':h='min(720,ih)':force_original_aspect_ratio=decrease:force_divisible_by=2");
        ARG("-pix_fmt"); ARG("yuv420p"); ARG("-b:v"); ARG("1500k"); ARG("-maxrate"); ARG("1800k");
        ARG("-bufsize"); ARG("3600k"); ARG("-force_key_frames"); ARG("expr:gte(t,n_forced*4)");
    }
    if (audio >= 0) { ARG("-map"); ARG(amap); ARG("-c:a"); ARG("aac"); ARG("-b:a"); ARG("128k"); ARG("-ac"); ARG("2"); }
    ARG("-sn"); ARG("-threads"); ARG("1"); ARG("-f"); ARG("hls");
    ARG("-hls_time"); ARG("4"); ARG("-hls_list_size"); ARG("12");
    ARG("-hls_delete_threshold"); ARG("2"); ARG("-hls_flags"); ARG("delete_segments+independent_segments+temp_file");
    ARG("-hls_base_url"); ARG(base); ARG("-hls_segment_filename"); ARG("part-%06d.ts"); ARG("index.m3u8"); ARG(NULL);
#undef ARG
    int null = open("/dev/null", O_WRONLY);
    if (run(args, s->source, null, log, 0)) child_error(s, "transcode_failed");
    free(base); close(null); close(log); _exit(0);
}
static void clear_dir(int fd) {
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = copy >= 0 ? fdopendir(copy) : NULL;
    if (!dir) { if (copy >= 0) close(copy); return; }
    struct dirent *e;
    while ((e = readdir(dir))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) unlinkat(fd, e->d_name, 0);
    closedir(dir);
}
static void stop(struct session *s) {
    if (s->pid > 0) {
        kill(-s->pid, SIGTERM);
        int status; struct timespec delay = {0, 20000000};
        for (int i = 0; i < 25; i++) {
            if (waitpid(s->pid, &status, WNOHANG) == s->pid) { s->pid = 0; break; }
            nanosleep(&delay, NULL);
        }
        if (s->pid) { kill(-s->pid, SIGKILL); while (waitpid(s->pid, &status, 0) < 0 && errno == EINTR) {} }
        s->pid = 0;
    }
}
static void release(struct session *s) {
    if (!s->id[0]) return;
    stop(s); clear_dir(s->dir); close(s->dir);
    unlinkat(s->parent, s->folder, AT_REMOVEDIR); close(s->parent); close(s->source);
    memset(s, 0, sizeof(*s));
}
void nas_playback_recover(int fd) {
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = copy >= 0 ? fdopendir(copy) : NULL;
    if (!dir) { if (copy >= 0) close(copy); return; }
    struct dirent *e;
    while ((e = readdir(dir))) {
        if (strncmp(e->d_name, "media-session-", 14) || strlen(e->d_name) != 46 ||
            strspn(e->d_name + 14, "0123456789abcdef") != 32) continue;
        int sub = openat(fd, e->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub >= 0) { clear_dir(sub); close(sub); unlinkat(fd, e->d_name, AT_REMOVEDIR); }
    }
    closedir(dir);
}
void nas_playback_close(void) { for (int i = 0; i < SESSION_COUNT; i++) release(&sessions[i]); }
int nas_playback_active(void) { for (int i = 0; i < SESSION_COUNT; i++) if (sessions[i].id[0]) return 1; return 0; }
int nas_playback_capable(void) { return encoder_available; }
void nas_playback_tick(int ready) {
    time_t now = time(NULL);
    for (int i = 0; i < SESSION_COUNT; i++) {
        struct session *s = &sessions[i];
        if (!s->id[0]) continue;
        if (!ready || now - s->seen > NAS_PLAYBACK_IDLE_SECONDS) { release(s); continue; }
        int status;
        if (s->pid > 0 && waitpid(s->pid, &status, WNOHANG) == s->pid) {
            s->pid = 0; s->finished = 1; s->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        }
        struct json_object *meta = read_json(s->dir, "info.json"), *v = NULL;
        if (meta) { if (json_object_object_get_ex(meta, "hls_available", &v)) encoder_available = json_object_get_boolean(v); json_object_put(meta); }
        int copy = openat(s->dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *dir = copy >= 0 ? fdopendir(copy) : NULL; struct dirent *e; long long total = 0;
        if (dir) { while ((e = readdir(dir))) { struct stat st; if (!fstatat(s->dir, e->d_name, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode)) total += st.st_size; } closedir(dir); }
        struct statvfs disk;
        if (s->pid > 0 && (total > CACHE_LIMIT || (!fstatvfs(s->dir, &disk) && (unsigned long long)disk.f_bavail * disk.f_frsize < 8 * 1024 * 1024))) {
            stop(s); s->finished = s->exit_code = 1; snprintf(s->error, sizeof(s->error), "cache_limit");
        }
        if (s->pid > 0 && !meta && now - s->started > 40) {
            stop(s); s->finished = s->exit_code = 1; snprintf(s->error, sizeof(s->error), "probe_timeout");
        }
    }
}
static struct json_object *ref(struct session *s, const char *filename) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/.dreamingos-nas/%s/%s", s->path, s->folder, filename) >= (int)sizeof(path)) return NULL;
    struct json_object *o = json_object_new_object(); add(o, "root_id", s->root); add(o, "path", path); return o;
}
static struct json_object *describe(struct session *s) {
    struct json_object *o = json_object_new_object(), *meta = read_json(s->dir, "info.json"), *err = read_json(s->dir, "error.json");
    struct stat st; int playlist = !fstatat(s->dir, "index.m3u8", &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode) && st.st_size > 0;
    add(o, "id", s->id); add(o, "mode", s->mode ? "hls" : "probe");
    add(o, "state", s->error[0] || err || (s->finished && s->exit_code) ? "failed" : s->finished ? (s->mode ? "ended" : "ready") : playlist ? "running" : "preparing");
    if (s->error[0] || err) add(o, "reason", s->error[0] ? s->error : str(err, "error"));
    else if (s->finished && s->exit_code) add(o, "reason", "worker_interrupted");
    if (meta) json_object_object_add(o, "metadata", meta);
    if (err) json_object_put(err);
    if (playlist) json_object_object_add(o, "playlist", ref(s, "index.m3u8"));
    if (!fstatat(s->dir, "subtitle.vtt", &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode)) json_object_object_add(o, "subtitle", ref(s, "subtitle.vtt"));
    json_object_object_add(o, "position_seconds", json_object_new_double(s->position));
    json_object_object_add(o, "idle_timeout_seconds", json_object_new_int(NAS_PLAYBACK_IDLE_SECONDS));
    json_object_object_add(o, "cache_limit_bytes", json_object_new_int64(CACHE_LIMIT));
    return o;
}
struct json_object *nas_playback_request(const char *method, const char *route,
    struct json_object *input, int data_fd, const char *root, const char *path, int *status) {
    *status = 200;
    struct session *s = NULL;
    for (int i = 0; i < SESSION_COUNT; i++) if (sessions[i].id[0] && !strcmp(str(input, "id"), sessions[i].id)) s = &sessions[i];
    if (!strcmp(method, "GET") && !strcmp(route, "/media/sessions")) {
        if (!s) return error("session_not_found", 404, status);
        s->seen = time(NULL); return describe(s);
    }
    if (!strcmp(method, "POST") && !strcmp(route, "/media/sessions/stop")) {
        if (!s) return error("session_not_found", 404, status);
        release(s); struct json_object *o = json_object_new_object(); add(o, "state", "stopped"); return o;
    }
    if (strcmp(method, "POST") || strcmp(route, "/media/sessions")) return error("not_found", 404, status);
    const char *mode = str(input, "mode"); double position, audio, subtitle;
    if ((strcmp(mode, "hls") && strcmp(mode, "probe")) || number(input, "position_seconds", 0, &position) || position < 0 || position > 604800 ||
        number(input, "audio_index", -1, &audio) || audio < -1 || audio > 1024 || audio != (int)audio ||
        number(input, "subtitle_index", -1, &subtitle) || subtitle < -1 || subtitle > 1024 || subtitle != (int)subtitle)
        return error("invalid_request", 400, status);
    if (access("/usr/bin/ffprobe", X_OK) || (!strcmp(mode, "hls") && access("/usr/bin/ffmpeg", X_OK))) return error("dependency_missing", 409, status);
    struct json_object *source = NULL;
    if (!json_object_object_get_ex(input, "source", &source) || !str(source, "root_id")[0] || !str(source, "path")[0]) return error("invalid_request", 400, status);
    s = NULL;
    for (int i = 0; i < SESSION_COUNT; i++) if (!sessions[i].id[0]) { s = &sessions[i]; break; }
    if (!s) return error("session_limit", 409, status);
    struct storage_files_stream file; const char *reason = "";
    if (storage_files_open_stream(str(source, "root_id"), str(source, "path"), &file, &reason)) return error("source_unavailable", 409, status);
    unsigned char random[16]; int random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    int ok = random_fd >= 0 && read(random_fd, random, sizeof(random)) == sizeof(random);
    if (random_fd >= 0) close(random_fd);
    if (!ok) { close(file.fd); return error("worker_unavailable", 503, status); }
    char id[33]; for (int i = 0; i < 16; i++) snprintf(id + i * 2, 3, "%02x", random[i]);
    char folder[64]; snprintf(folder, sizeof(folder), "media-session-%s", id);
    int parent = dup(data_fd), dir = -1;
    if (parent >= 0 && !mkdirat(parent, folder, 0700)) dir = openat(parent, folder, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) { if (parent >= 0) close(parent); close(file.fd); return error("cache_unwritable", 409, status); }
    memset(s, 0, sizeof(*s)); snprintf(s->id, sizeof(s->id), "%s", id); snprintf(s->folder, sizeof(s->folder), "%s", folder);
    snprintf(s->root, sizeof(s->root), "%s", root); snprintf(s->path, sizeof(s->path), "%s", path);
    s->source = file.fd; s->dir = dir; s->parent = parent; s->position = position; s->audio = audio; s->subtitle = subtitle;
    s->mode = !strcmp(mode, "hls"); s->seen = s->started = time(NULL); s->pid = fork();
    if (!s->pid) child(s);
    if (s->pid < 0) { s->pid = 0; release(s); return error("worker_unavailable", 503, status); }
    setpgid(s->pid, s->pid); *status = 202; return describe(s);
}
