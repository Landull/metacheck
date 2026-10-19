# metacheck

A forensic metadata extractor for images, PDFs and Office documents. It pulls out the metadata and then points out the parts that matter in an investigation, like where a photo was taken, whether it was edited, or whether a PDF's author changed between saves.

No dependencies. Just Python 3.8+ and the standard library. It pairs with [hashcheck](https://github.com/Landull/hashcheck).

## What it reads

| Type | Metadata extracted |
|---|---|
| JPEG | EXIF, GPS, XMP (including edit history), comments, embedded thumbnail |
| PNG | text chunks, eXIf, tIME, XMP |
| TIFF / DNG / NEF / CR2 / ARW | EXIF, GPS, XMP |
| WebP | EXIF, XMP |
| HEIC / AVIF | EXIF and XMP (best effort) |
| PDF | Info dictionary across every revision, XMP, active content |
| DOCX / XLSX / PPTX (+ macro versions) | core, app and custom properties |
| ODT / ODS / ODP | meta.xml |

Every file also gets its size, filesystem timestamps and a SHA-256 hash.

## What it flags

- **GPS coordinates**, with a Google Maps link (and optional KML export for Google Earth)
- **Editing software** such as Photoshop, Lightroom, GIMP, Snapseed or Facetune
- **Modified after capture**, when the EXIF save time differs from the capture time
- **Embedded thumbnails**, which can show a photo as it looked before edits, plus a warning when the thumbnail's shape doesn't match the image (a sign of cropping)
- **Device identifiers** like camera body and lens serial numbers
- **Stripped metadata**, typical of photos from social media or messaging apps
- **Data hidden after the end of the file**, naming it when it looks like a ZIP, RAR, executable and so on
- **Wrong file extension** for what the file actually contains
- **Truncated files**, such as incomplete copies or carved fragments
- **AI-generated images**, from generator settings in PNG text, the IPTC "trainedAlgorithmicMedia" label, or C2PA Content Credentials
- **PDF revisions**: incremental saves, and Author/Title/Producer values that changed between them
- **PDF active content**: JavaScript, auto-run actions, Launch actions, embedded files, and obfuscated names
- **Office documents**: VBA macros, remote templates, external links, and a different last editor than the original author

## Usage

```
python3 metacheck.py photo.jpg
```

Some real uses:

```
# Everything in a folder (recurses by default; -n to stay at the top level)
python3 metacheck.py ~/Evidence

# Just the red flags
python3 metacheck.py ~/Evidence --findings-only

# Spreadsheet for case notes, plus a map of every photo location
python3 metacheck.py ~/Evidence -f csv -o metadata.csv --kml locations.kml

# Save embedded thumbnails to compare against the full images
python3 metacheck.py ~/Evidence --thumbs thumbs/

# JSON for scripts or other tools
python3 metacheck.py report.pdf -f json
```

On Windows, use `python` instead of `python3`.

| Option | Meaning |
|---|---|
| `-n`, `--no-recurse` | don't descend into subfolders |
| `-f`, `--format` | `text` (default), `csv`, or `json` |
| `-o`, `--output FILE` | write the report to a file |
| `--findings-only` | only show files with findings, and only the findings |
| `--thumbs DIR` | save embedded EXIF thumbnails into DIR |
| `--kml FILE` | write all GPS locations to a KML file |
| `--all-tags` | include unnamed EXIF tags as `Tag0xNNNN` |
| `--no-hash` | skip SHA-256 hashing |

When you scan a folder, file types it can't read are skipped. Files you name directly are always reported.

## Example

```
==> IMG_0412.jpg  [jpeg]
  ...
  Findings:
    ! GPS location embedded: 29.7600333, -95.3699667
    ! Processed with editing software: Adobe Photoshop 25.1 (Macintosh)
    ! Modified after capture (taken 2026:09:28 14:03:55, last saved 2026:10:02 21:14:09)
    ! Device-identifying details present: BodySerialNumber=082021004512
    ! Embedded thumbnail present - it can show the image as it looked before later edits
    ! Thumbnail shape (160x120) does not match the image (800x800) - the image may have been cropped
    ! 132 bytes of data after the end of the file at offset 12,580 (looks like: ZIP archive)
```

## Forensic notes

- **Work on copies.** Reading a file can update its last-accessed time on some systems. Run metacheck against a forensic image or a write-blocked copy, and record the SHA-256 it reports.
- **Metadata is easy to fake.** Treat findings as leads to corroborate, not proof. A missing flag doesn't mean a file is clean.
- **Limits.** Vendor MakerNotes aren't decoded, PDF metadata inside compressed object streams can be missed, HEIC parsing is signature-based, and video files aren't supported yet. For deep work, compare against ExifTool.

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s forensics toolkit.
