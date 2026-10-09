"""Small real JPEG fixtures for host media tests and on-device NAS scans."""
from pathlib import Path
from PIL import Image, ImageDraw, TiffImagePlugin


def create_photos(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    image = Image.new('RGB', (160, 120))
    draw = ImageDraw.Draw(image)
    for box, color in [((0, 0, 79, 59), (230, 30, 30)),
                       ((80, 0, 159, 59), (30, 200, 30)),
                       ((0, 60, 79, 119), (30, 30, 230)),
                       ((80, 60, 159, 119), (220, 200, 30))]:
        draw.rectangle(box, fill=color)
    rational = TiffImagePlugin.IFDRational
    cases = []

    def save(name, *, original='2024:07:08 09:10:11', digitized=None,
             gps=True, lat=(31, 13, 30), lon=(121, 28, 15), refs=('N', 'E'),
             orientation=1, offset='+08:00', expected_time='2024-07-08T09:10:11',
             expected_gps=(31.225, 121.47083333333333), camera=True):
        exif = Image.Exif()
        exif[0x112] = orientation
        if camera:
            exif[0x10f] = 'Fixture & <Camera>'
            exif[0x110] = 'Four corners'
        # This is the editing time, and must not be mistaken for capture time.
        exif[0x132] = '2026:10:05 01:02:03'
        nested = {}
        if original is not None:
            nested[0x9003] = original
            if offset is not None:
                nested[0x9011] = offset
        if digitized is not None:
            nested[0x9004] = digitized
        if nested:
            exif[0x8769] = nested
        if gps:
            coordinates = {2: tuple(rational(x) for x in lat),
                           4: tuple(rational(x) for x in lon)}
            if refs[0] is not None:
                coordinates[1] = refs[0]
            if refs[1] is not None:
                coordinates[3] = refs[1]
            exif[0x8825] = coordinates
        path = directory / (name + '.jpg')
        image.save(path, quality=95, exif=exif)
        cases.append({'path': str(path), 'taken_at': expected_time,
                      'gps': expected_gps, 'orientation': orientation})

    for orientation in range(1, 9):
        save('orientation-' + str(orientation), orientation=orientation)
    save('south-west', refs=('S', 'W'), expected_gps=(-31.225, -121.47083333333333))
    save('zero', lat=(0, 0, 0), lon=(0, 0, 0), expected_gps=(0.0, 0.0))
    save('boundary', lat=(90, 0, 0), lon=(180, 0, 0), expected_gps=(90.0, 180.0))
    save('out-of-range', lat=(90, 0, 1), expected_gps=None)
    save('bad-minutes', lat=(31, 60, 0), expected_gps=None)
    save('missing-ref', refs=(None, 'E'), expected_gps=None)
    save('wrong-ref', refs=('E', 'N'), expected_gps=None)
    save('zero-denominator', lat=(rational(1, 0), 0, 0), expected_gps=None)
    save('bad-date', original='2023:02:29 09:10:11', expected_time=None)
    save('leap-date', original='2024:02:29 09:10:11', expected_time='2024-02-29T09:10:11')
    save('digitized', original=None, digitized='2020:03:04 05:06:07',
         expected_time='2020-03-04T05:06:07', gps=False, expected_gps=None)
    save('missing', original=None, gps=False, camera=False, expected_time=None, expected_gps=None)
    save('unknown-timezone', offset=None)
    save('invalid-timezone', offset='+99:00')
    return cases


if __name__ == '__main__':
    import json
    import sys
    print(json.dumps(create_photos(sys.argv[1]), indent=2))
