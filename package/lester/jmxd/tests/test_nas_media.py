#!/usr/bin/env python3
"""Tests real FFmpeg thumbnails, FFprobe metadata and local NFO/LRC sidecars."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
from PIL import Image, ImageOps
from nas_exif_fixtures import create_photos
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='nas-media-') as tmp:
    base=Path(tmp);disk=base/'disk';disk.mkdir();cache=disk/'cache';cache.mkdir();dev=disk.stat().st_dev;mi=base/'mountinfo';mi.write_text(f'91 1 {os.major(dev)}:{os.minor(dev)} / {disk} rw - ext4 /dev/test rw\n')
    photo=disk/'photo.png';song=disk/'song.wav';movie=disk/'episode.mp4'
    for args in [('-f','lavfi','-i','color=c=blue:s=640x480','-frames:v','1',str(photo)),('-f','lavfi','-i','sine=duration=1','-metadata','title=Local song',str(song)),('-f','lavfi','-i','color=c=red:s=160x90:d=1','-c:v','libx264','-pix_fmt','yuv420p',str(movie))]:subprocess.run(['ffmpeg','-nostdin','-v','error','-y',*args],check=True)
    (disk/'song.lrc').write_text('[00:00.00]离线歌词\n');(disk/'episode.nfo').write_text('<episodedetails><title>本地剧集</title><sorttitle>剧集排序</sorttitle><showtitle>测试剧</showtitle><season>2</season><episode>3</episode><plot>本地 NFO 内容</plot><genre>剧情</genre><genre>科幻</genre><director>导演甲</director><director>导演乙</director><rating>8.5</rating></episodedetails>');(disk/'episode-poster.jpg').write_bytes(photo.read_bytes())
    tagged=disk/'tagged.flac'
    subprocess.run(['ffmpeg','-nostdin','-v','error','-y','-i',str(song),'-metadata','TITLE=标签歌曲','-metadata','ARTIST=本地歌手','-metadata','ALBUM=本地专辑','-metadata','ALBUMARTIST=专辑歌手','-metadata','GENRE=古典','-metadata','DATE=2024-03-09','-metadata','TRACK=03/12',str(tagged)],check=True)
    flags=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-I/usr/include/libxml2','-DSTORAGE_FILES_TEST_ALLOW_PROTECTED_DEVICE=1','-DSTORAGE_FILES_TEST_ALLOW_ANY_MOUNT_ROOT=1',f'-DSTORAGE_FILES_MOUNTINFO="{mi}"','-I',str(ROOT/'src')]
    fixture=base/'files';subprocess.run(flags+[str(ROOT/'src/storage/storage_files.c'),str(ROOT/'tests/test_storage_files_fixture.c'),'-ljson-c','-o',str(fixture)],check=True);rid=json.loads(subprocess.check_output([str(fixture)],text=True))['data']['root_id']
    harness=base/'test.c';harness.write_text('#include "nas/nas_media.h"\n#include <fcntl.h>\n#include <unistd.h>\n#include <stdio.h>\nstruct json_object *jmx_gen_api_response_data(int code,struct json_object *data){(void)code;return data;}\nint main(int argc,char **argv){(void)argc;volatile sig_atomic_t stop=0;int fd=open(argv[4],O_RDONLY|O_DIRECTORY);struct json_object *r=nas_media_read(argv[1],argv[2],argv[3],fd,1,&stop);puts(json_object_to_json_string(r));json_object_put(r);close(fd);return 0;}\n')
    binary=base/'media';subprocess.run(flags+[str(harness),str(ROOT/'src/nas/nas_media.c'),str(ROOT/'src/storage/storage_files.c'),'-ljson-c','-lxml2','-o',str(binary)],check=True)
    photo_cases=create_photos(disk/'exif')
    before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in (photo,song,movie,tagged,disk/'episode.nfo',disk/'song.lrc',*(Path(c['path']) for c in photo_cases))}
    def call(path,domain):return json.loads(subprocess.check_output([str(binary),rid,str(path),domain,str(cache)],text=True))
    p=call(photo,'photos');assert p['thumbnail']=='thumbnail-1.jpg',p
    dimensions=json.loads(subprocess.check_output(['ffprobe','-v','error','-show_entries','stream=width,height','-of','json',str(cache/p['thumbnail'])],text=True))['streams'][0];assert dimensions=={'width':320,'height':240},dimensions
    m=call(song,'music');assert m['lyrics']=='[00:00.00]离线歌词\n';assert m['title']=='Local song';assert float(m['duration'])>=1
    c=call(movie,'cinema');assert c['title']=='本地剧集' and c['season']=='2' and c['episode']=='3';assert c['metadata_source']=='local_nfo';assert c['artwork_path']==str(disk/'episode-poster.jpg')
    assert {k:c[k] for k in ['sort_title','genre','director','rating']}=={'sort_title':'剧集排序','genre':'剧情 / 科幻','director':'导演甲 / 导演乙','rating':'8.5'},c
    t=call(tagged,'music')
    assert {k:t[k] for k in ['title','artist','album','album_artist','genre','year','track']}=={'title':'标签歌曲','artist':'本地歌手','album':'本地专辑','album_artist':'专辑歌手','genre':'古典','year':'2024','track':'3'},t
    for case in photo_cases:
        path=Path(case['path']);metadata=call(path,'photos');exif=metadata.get('photo_exif',{})
        assert metadata.get('taken_at')==case['taken_at'],(path,metadata)
        if case['gps'] is None:
            assert 'latitude' not in exif and 'longitude' not in exif and 'location' not in metadata,(path,metadata)
        else:
            assert abs(exif['latitude']-case['gps'][0])<1e-7 and abs(exif['longitude']-case['gps'][1])<1e-7,(path,metadata)
        if path.stem=='digitized':assert exif['time_source']=='digitized' and 'utc_offset' not in exif,metadata
        if path.stem in ['unknown-timezone','invalid-timezone']:assert 'utc_offset' not in exif,metadata
        if path.stem.startswith('orientation-'):
            assert exif['utc_offset']=='+08:00' and exif['time_source']=='original',metadata
            expected=ImageOps.exif_transpose(Image.open(path)).convert('RGB')
            actual=Image.open(cache/metadata['thumbnail']).convert('RGB')
            assert actual.size==((240,320) if case['orientation']>=5 else (320,240)),(path,actual.size)
            for x,y in [(0.25,0.25),(0.75,0.25),(0.25,0.75),(0.75,0.75)]:
                a=actual.getpixel((int(actual.width*x),int(actual.height*y)))
                e=expected.getpixel((int(expected.width*x),int(expected.height*y)))
                assert max(abs(a[i]-e[i]) for i in range(3))<20,(path,x,y,a,e)
    assert before=={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in before}
    print('PASS: 22 real EXIF/GPS JPEG cases including 8 orientations with corner pixels; invalid/missing date, offset, rationals and coordinates; original/sidecar bytes unchanged; thumbnail, music tags and NFO regressions')
