// SPDX-License-Identifier: GPL-2.0-or-later
/* Local-only media metadata; called by the bounded background scan worker. */
#define _GNU_SOURCE
#include "nas_media.h"
#include "storage/storage_files.h"
#include <errno.h>
#include <fcntl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static const char *value(struct json_object *o, const char *key) {
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) ? json_object_get_string(v) : "";
}
static void add(struct json_object *o, const char *key, const char *s) {
    if (s && *s)
        json_object_object_add(o, key, json_object_new_string(s));
}
static const char *tag_value(struct json_object *tags, const char *key) {
    if (!json_object_is_type(tags, json_type_object))
        return "";
    json_object_object_foreach(tags, name, entry) {
        if (!strcasecmp(name, key) && json_object_is_type(entry, json_type_string))
            return json_object_get_string(entry);
    }
    return "";
}
static const char *exif_tag(struct json_object *tags, const char *group, const char *key) {
    /* FFmpeg 9 qualifies nested IFD tags; earlier versions used bare names. */
    char qualified[96];
    snprintf(qualified, sizeof(qualified), "%s/%s", group, key);
    const char *text = tag_value(tags, qualified);
    return *text ? text : tag_value(tags, key);
}
static int exif_date(const char *text, char normalized[20]) {
    struct tm date = {0};
    char *end = strptime(text, "%Y:%m:%d %H:%M:%S", &date);
    if (!end || *end || strlen(text) != 19 || date.tm_year + 1900 < 1)
        return 0;
    int year = date.tm_year + 1900;
    const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (date.tm_mday > days[date.tm_mon] + (date.tm_mon == 1 && leap))
        return 0;
    char canonical[20];
    strftime(canonical, sizeof(canonical), "%Y:%m:%d %H:%M:%S", &date);
    if (strcmp(text, canonical))
        return 0;
    strftime(normalized, 20, "%Y-%m-%dT%H:%M:%S", &date);
    return 1;
}
static int exif_coordinate(const char *text, const char *ref, int latitude, double *result) {
    double n[3], d[3];
    int consumed = 0;
    if (sscanf(text, " %lf:%lf , %lf:%lf , %lf:%lf %n",
               &n[0], &d[0], &n[1], &d[1], &n[2], &d[2], &consumed) != 6 ||
        !consumed || text[consumed] || strlen(ref) != 1 ||
        !strchr(latitude ? "NS" : "EW", ref[0]))
        return 0;
    for (int i = 0; i < 3; i++) {
        if (!isfinite(n[i]) || !isfinite(d[i]) || n[i] < 0 || d[i] <= 0)
            return 0;
        n[i] /= d[i];
        if (!isfinite(n[i]) || (i && n[i] >= 60))
            return 0;
    }
    double value = n[0] + n[1] / 60 + n[2] / 3600;
    if (value > (latitude ? 90 : 180))
        return 0;
    *result = ref[0] == 'S' || ref[0] == 'W' ? -value : value;
    return 1;
}
static void photo_metadata(struct json_object *out, struct json_object *probe) {
    struct json_object *frames = NULL, *tags = NULL;
    if (!json_object_object_get_ex(probe, "frames", &frames) ||
        !json_object_is_type(frames, json_type_array) || !json_object_array_length(frames))
        return;
    json_object_object_get_ex(json_object_array_get_idx(frames, 0), "tags", &tags);
    struct json_object *exif = json_object_new_object();
    const char *camera[] = {"Make", "Model"};
    for (int i = 0; i < 2; i++) {
        const char *text = tag_value(tags, camera[i]);
        if (strlen(text) <= 512)
            add(exif, i ? "model" : "make", text);
    }
    char date[20];
    const char *date_keys[] = {"DateTimeOriginal", "DateTimeDigitized"};
    for (int i = 0; i < 2; i++) {
        if (!exif_date(exif_tag(tags, "ExifIFD", date_keys[i]), date))
            continue;
        add(out, "taken_at", date);
        add(exif, "taken_at", date);
        add(exif, "time_source", i ? "digitized" : "original");
        const char *offset = exif_tag(tags, "ExifIFD", i ? "OffsetTimeDigitized" : "OffsetTimeOriginal");
        if (!*offset)
            offset = exif_tag(tags, "ExifIFD", i ? "0x9012" : "0x9011");
        if (strlen(offset) == 6 && (offset[0] == '+' || offset[0] == '-') &&
            offset[3] == ':' && offset[1] >= '0' && offset[1] <= '2' &&
            offset[2] >= '0' && offset[2] <= '9' &&
            (offset[1] != '2' || offset[2] <= '3') &&
            offset[4] >= '0' && offset[4] <= '5' && offset[5] >= '0' && offset[5] <= '9')
            add(exif, "utc_offset", offset);
        break;
    }
    double latitude, longitude;
    if (exif_coordinate(exif_tag(tags, "GPSInfo", "GPSLatitude"),
                        exif_tag(tags, "GPSInfo", "GPSLatitudeRef"), 1, &latitude) &&
        exif_coordinate(exif_tag(tags, "GPSInfo", "GPSLongitude"),
                        exif_tag(tags, "GPSInfo", "GPSLongitudeRef"), 0, &longitude)) {
        json_object_object_add(exif, "latitude", json_object_new_double(latitude));
        json_object_object_add(exif, "longitude", json_object_new_double(longitude));
        char location[64];
        snprintf(location, sizeof(location), "%.6f, %.6f", latitude, longitude);
        add(out, "location", location);
    }
    if (json_object_object_length(exif)) {
        json_object_object_add(out, "photo_exif", exif);
        add(out, "metadata_source", "embedded_exif");
    } else
        json_object_put(exif);
}
static void add_number_tag(struct json_object *out, const char *key, const char *text,
                           char separator) {
    if (!text[0])
        return;
    char *end;
    long number = strtol(text, &end, 10);
    if (end == text || number < 0 || number > 9999 || (*end && *end != separator))
        return;
    char normalized[16];
    snprintf(normalized, sizeof(normalized), "%ld", number);
    add(out, key, normalized);
}
static void nfo_field(struct json_object *out, xmlNode *node, const char *key,
                       int multiple) {
    xmlChar *text = xmlNodeGetContent(node);
    size_t limit = !strcmp(key, "plot") ? 8192 : 512;
    if (text && xmlStrlen(text) > 0 && (size_t)xmlStrlen(text) <= limit) {
        const char *previous = value(out, key);
        if (multiple && previous[0]) {
            char combined[513];
            if (strlen(previous) + 3 + (size_t)xmlStrlen(text) <= limit) {
                snprintf(combined, sizeof(combined), "%s / %s", previous, (const char *)text);
                add(out, key, combined);
            }
        } else
            add(out, key, (const char *)text);
    }
    xmlFree(text);
}
static int run(char *const argv[], int input, int output, volatile sig_atomic_t *cancelled) {
    pid_t pid = fork();
    if (!pid) {
        fcntl(input, F_SETFD, 0);
        dup2(output, STDOUT_FILENO);
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            dup2(null, STDIN_FILENO);
            if (null > 2)
                close(null);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    struct timespec start, now, delay = {0, 20000000};
    clock_gettime(CLOCK_MONOTONIC, &start);
    int status;
    while (waitpid(pid, &status, WNOHANG) == 0) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (*cancelled || now.tv_sec - start.tv_sec > 15) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            return -1;
        }
        nanosleep(&delay, NULL);
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}
static char *read_sidecar(const char *root, const char *path) {
    struct storage_files_stream file;
    const char *reason = "";
    if (storage_files_open_stream(root, path, &file, &reason))
        return NULL;
    if (file.size_bytes > 262144) {
        close(file.fd);
        return NULL;
    }
    char *data = calloc((size_t)file.size_bytes + 1, 1);
    if (!data) {
        close(file.fd);
        return NULL;
    }
    size_t offset = 0;
    while (offset < file.size_bytes) {
        ssize_t n = read(file.fd, data + offset, (size_t)file.size_bytes - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            free(data);
            close(file.fd);
            return NULL;
        }
        offset += (size_t)n;
    }
    close(file.fd);
    return data;
}
static void sidecar_path(char out[PATH_MAX], const char *path, const char *extension) {
    snprintf(out, PATH_MAX, "%s", path);
    char *dot = strrchr(out, '.'), *slash = strrchr(out, '/');
    if (dot && (!slash || dot > slash))
        *dot = 0;
    size_t used = strlen(out);
    snprintf(out + used, PATH_MAX - used, "%s", extension);
}
static void nearby_image(struct json_object *out, const char *root, const char *path,
                         const char *suffix, const char *fallback) {
    char name[PATH_MAX];
    sidecar_path(name, path, suffix);
    struct storage_files_stream file;
    const char *reason = "";
    int rc = storage_files_open_stream(root, name, &file, &reason);
    if (rc && fallback) {
        snprintf(name, sizeof(name), "%s", path);
        char *slash = strrchr(name, '/');
        if (slash)
            snprintf(slash + 1, sizeof(name) - (size_t)(slash + 1 - name), "%s", fallback);
        rc = storage_files_open_stream(root, name, &file, &reason);
    }
    if (!rc) {
        close(file.fd);
        add(out, "artwork_path", name);
    }
}
struct json_object *nas_media_read(const char *root, const char *path, const char *domain,
                                   int cache_fd, long id, volatile sig_atomic_t *cancelled) {
    struct json_object *out = json_object_new_object();
    char sidecar[PATH_MAX];
    if (!strcmp(domain, "cinema")) {
        sidecar_path(sidecar, path, ".nfo");
        char *data = read_sidecar(root, sidecar);
        if (data) {
            xmlDoc *doc = xmlReadMemory(data, (int)strlen(data), NULL, NULL,
                                        XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
            free(data);
            if (doc) {
                xmlNode *node = xmlDocGetRootElement(doc);
                if (node) {
                    add(out, "media_type",
                        !xmlStrcmp(node->name, BAD_CAST "episodedetails") ? "episode" : "movie");
                    const char *fields[] = {"title", "plot", "year", "season", "episode",
                                            "showtitle", "sorttitle", "genre", "director",
                                            "rating", NULL};
                    for (xmlNode *child = node->children; child; child = child->next) {
                        for (int i = 0; fields[i]; i++)
                            if (!xmlStrcmp(child->name, BAD_CAST fields[i])) {
                                nfo_field(out, child,
                                          !strcmp(fields[i], "sorttitle") ? "sort_title" : fields[i],
                                          !strcmp(fields[i], "genre") || !strcmp(fields[i], "director"));
                            }
                    }
                    add(out, "metadata_source", "local_nfo");
                }
                xmlFreeDoc(doc);
            } else
                add(out, "nfo_error", "invalid_xml");
        }
        nearby_image(out, root, path, "-poster.jpg", "poster.jpg");
    } else if (!strcmp(domain, "music")) {
        sidecar_path(sidecar, path, ".lrc");
        char *data = read_sidecar(root, sidecar);
        if (data) { /* Lyrics are opaque local UTF-8 text. */
            if (xmlCheckUTF8((const xmlChar *)data))
                add(out, "lyrics", data);
            else
                add(out, "lyrics_error", "not_utf8");
            free(data);
        }
        nearby_image(out, root, path, ".jpg", "cover.jpg");
    }
    struct storage_files_stream source;
    const char *reason = "";
    if (storage_files_open_stream(root, path, &source, &reason)) {
        add(out, "probe_error", "source_unavailable");
        return out;
    }
    char input[80];
    snprintf(input, sizeof(input), "/proc/self/fd/%d", source.fd);
    if (access("/usr/bin/ffprobe", X_OK) == 0 && !*cancelled) {
        char temporary[80];
        snprintf(temporary, sizeof(temporary), "probe-%ld.tmp", (long)getpid());
        int output =
            openat(cache_fd, temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output >= 0) {
            char *argv[] = {"/usr/bin/ffprobe",
                            "-v",
                            "error",
                            "-show_entries",
                            "format=duration:format_tags=title,artist,album,album_artist,albumartist,"
                            "genre,date,year,track,TITLE,ARTIST,ALBUM,ALBUM_ARTIST,ALBUMARTIST,"
                            "GENRE,DATE,YEAR,TRACK:stream=codec_type,"
                            "width,height,codec_name",
                            "-of",
                            "json",
                            input,
                            NULL};
            char *photo_argv[] = {"/usr/bin/ffprobe", "-v", "error", "-threads", "1",
                                  "-select_streams", "v:0", "-read_intervals", "%+#1",
                                  "-show_entries", "stream=codec_type,width,height,codec_name:frame_tags",
                                  "-of", "json", input, NULL};
            int rc = run(!strcmp(domain, "photos") ? photo_argv : argv, source.fd, output,
                         cancelled);
            struct stat st;
            if (!rc && !fstat(output, &st) && st.st_size <= 262144) {
                lseek(output, 0, SEEK_SET);
                struct json_object *probe = json_object_from_fd(output), *format = NULL,
                                   *tags = NULL;
                if (probe) {
                    if (!strcmp(domain, "photos"))
                        photo_metadata(out, probe);
                    json_object_object_get_ex(probe, "format", &format);
                    if (format)
                        json_object_object_get_ex(format, "tags", &tags);
                    if (!*value(out, "title"))
                        add(out, "title", tag_value(tags, "title"));
                    if (!strcmp(domain, "music")) {
                        const char *fields[] = {"artist", "album", "album_artist", "genre", NULL};
                        for (int i = 0; fields[i]; i++)
                            add(out, fields[i], tag_value(tags, fields[i]));
                        if (!*value(out, "album_artist"))
                            add(out, "album_artist", tag_value(tags, "albumartist"));
                        const char *year = tag_value(tags, "date");
                        if (!*year)
                            year = tag_value(tags, "year");
                        add_number_tag(out, "year", year, '-');
                        add_number_tag(out, "track", tag_value(tags, "track"), '/');
                    }
                    add(out, "duration", value(format, "duration"));
                    struct json_object *streams = NULL;
                    if (json_object_object_get_ex(probe, "streams", &streams))
                        json_object_object_add(out, "streams", json_object_get(streams));
                    json_object_put(probe);
                }
            } else
                add(out, "probe_error", "probe_failed");
            close(output);
            unlinkat(cache_fd, temporary, 0);
        }
    } else
        add(out, "probe_error", "dependency_missing");
    if (!strcmp(domain, "photos") && access("/usr/bin/ffmpeg", X_OK) == 0 && !*cancelled) {
        char temporary[80], filename[80];
        snprintf(filename, sizeof(filename), "thumbnail-%ld.jpg", id);
        snprintf(temporary, sizeof(temporary), "thumbnail-%ld-%ld.tmp", id, (long)getpid());
        int output =
            openat(cache_fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (output >= 0) {
            lseek(source.fd, 0, SEEK_SET);
            char *argv[] = {"/usr/bin/ffmpeg",
                            "-nostdin",
                            "-v",
                            "error",
                            "-i",
                            input,
                            "-frames:v",
                            "1",
                            "-vf",
                            "scale=320:320:force_original_aspect_ratio=decrease",
                            "-threads",
                            "1",
                            "-f",
                            "image2pipe",
                            "-c:v",
                            "mjpeg",
                            "pipe:1",
                            NULL};
            int rc = run(argv, source.fd, output, cancelled);
            if (!rc && !fsync(output) && !renameat(cache_fd, temporary, cache_fd, filename))
                add(out, "thumbnail", filename);
            else
                add(out, "thumbnail_error", "decode_failed");
            close(output);
            unlinkat(cache_fd, temporary, 0);
        }
    } else if (!strcmp(domain, "photos"))
        add(out, "thumbnail_error", "dependency_missing");
    close(source.fd);
    return out;
}
