import argparse
import configparser
import logging
import os
import shutil
import subprocess
from distutils.spawn import find_executable
from filecmp import cmp
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory

from mardor.reader import MarReader
from mardor.writer import MarWriter


"""
A replacement for make_full_update.sh and make_incremental_update.sh

Currently undecided between mar binary and Python mar module.
* Python module vs downloading a binary from central's artifacts
* Need to download mbsdiff anyway as a Python version of that would be slow.
* Need to consider downstream users like Tor as well.

https://github.com/mozilla/build-mar


Could use both if there's a priority order:
1. os.environ["MAR"] if set, assume it's an override that we should use in
    favour of other options.
2. Check for --mar argument. Implies xz is required.
3. Attempt to use MarReader and MarWriter.
But that will likely just confuse issues.

TODO:
1. Tests
2. Logging for important milestones
3. Decide on script placement - where existing bash scripts are, or in funsize?
4. Make a container the standard way of doing a partial/full creation? 
5. Communication of changes

We currently compress files and diffs to compare the sizes, and store whichever
is smaller. We could examine the full mar for their compressed contents beforehand
and avoid some compression work. This means a UX change as we'd be given a full 
MAR rather than an extracted folder, but the win is good.

Should we rely on an xz binary, or is there a fast enough Python module?
"""


# TODO add logging to important milestones.
log = logging.getLogger(__name__)

# Compression options for xz
BCJ_OPTIONS = {
    "x86": ["--x86"],
    "x86_64": ["--x86"],
    "aarch64": [],
}


def find_vcs_root():
    # Could be using mercurial or git
    vcs_dirs = [".hg", ".git"]
    cwd = Path(__file__).resolve()

    for _ in range(4):  # Go at most four directories up
        cwd = cwd.parent
        if any([(cwd / d).exists() for d in vcs_dirs]):
            return cwd


@lru_cache()
def find_xz():
    """Find xz executable.

    This may be provided for us in the XZ environment variable,
    especially on Windows systems. See:
    python/mozbuild/mozbuild/repackaging/mar.py#74-76
    """
    if "XZ" in os.environ:
        return os.environ["XZ"]
    xz = find_executable("xz")
    if xz:
        return xz
    # Guess at Windows location if not provided
    windows_builder_path = find_vcs_root() / "xz/xz.exe"
    if windows_builder_path.exists():
        return windows_builder_path

    raise FileNotFoundError("Unable to locate xz executable")


# TODO need a way of passing in where mbsdiff is. Are env variables still a good idea?
@lru_cache()
def find_mbsdiff(searchpath=None):
    if searchpath:
        return find_executable("mbsdiff", searchpath)
    return find_executable("mbsdiff")


@lru_cache()
def find_mar(searchpath=None):
    if "MAR" in os.environ:
        return os.environ["MAR"]
    if searchpath:
        return find_executable("mar", searchpath)
    return find_executable("mar")


def find_file(directory, filename):
    log.debug("Searching for %s in %s", filename, directory)
    return next(Path(directory).rglob(filename))


def get_option(directory, filename, section, option):
    log.info("Extracting [%s]: %s from %s/**/%s", section, option, directory, filename)
    f = find_file(directory, filename)
    config = configparser.ConfigParser()
    config.read(f)
    rv = config.get(section, option)
    log.info("Found %s", rv)
    return rv


def mar_content_sizes(mar_path):
    """Report on the file sizes contained within a MAR.

    Allows comparison of newly created compressed artifacts to see which
    is worth storing.
    """
    # TODO decision path between binary mar and python mar
    mar_path = Path(mar_path)
    with mar_path.open(mode="rb") as fh:
        with MarReader(fh) as m:
            return {entry.name: entry.size for entry in m.mardata.index.entries}


def extract_mar_with_binary(mar_path, destination):
    command = [
        find_mar(),
        "-C",
        destination,
        "-x",
        mar_path,
    ]
    subprocess.run(command)


def create_mar_with_binary(
    source_path, destination, product_version, channel_id, files
):
    command = [
        find_mar(),
        "-V",
        product_version,
        "-H",
        channel_id,
        "-C",
        source_path,
        "-c",
        destination,
    ] + files
    subprocess.run(command)


def extract_mar(mar_path, destination):
    """Extract a MAR file into the given destination."""
    # TODO decision path between binary mar and python mar

    if not destination.exists():
        destination.mkdir(parents=True, exist_ok=True)
    elif destination.exists() and not destination.is_dir():
        log.error("Destination path %s exists and is not a directory", destination)
        raise ValueError(
            "Destination path %s exists and is not a directory", destination
        )

    log.info("Extracting %s into %s", mar_path, destination)
    with mar_path.open(mode="rb") as fh:
        with MarReader(fh) as m:
            m.extract(str(destination), decompress="auto")


def create_mar(source_path, destination, channel_id, product_version=None):
    # TODO decision path between binary mar and python mar
    source_path = Path(source_path)
    destination = Path(destination)

    if product_version is None:
        product_version = get_option(
            source_path, filename="application.ini", section="App", option="Version"
        )

    files = find_files(source_path)

    log.info("Creating %s from %s", destination, source_path)
    with destination.open(mode="w+b") as fh:
        with MarWriter(
            fh,
            productversion=product_version,
            channel=channel_id,
            signing_key=None,
            signing_algorithm=None,
        ) as m:
            for f in files:
                log.debug("Adding %s", f)
                # TODO we're already compressing these files earlier! do we need to?
                m.add(f, compress="xz")


def compress(source, destination, bcj_arch=None):
    """Compress a file using xz."""
    log.info("Compressing %s as %s", source, destination)
    command = [
        find_xz(),
    ]
    if bcj_arch and BCJ_OPTIONS.get(bcj_arch):
        command += BCJ_OPTIONS.get(bcj_arch)
    command += [
        "--lzma2",
        "--format=xz",
        "--check=crc64",
        "--force",
        "--stdout",
        source,
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Ensure the operation is safe in case source == destination
    with TemporaryDirectory() as temp_dir:
        output_file = temp_dir / destination.name
        with output_file.open(mode="wb") as fh:
            subprocess.run(command, stdout=fh)
        log.debug("Moving %s to %s", output_file, destination)
        shutil.move(output_file, destination)


def mbsdiff(old_path, new_path, patch_path):
    """Call mbsdiff and produce a patch."""
    log.info("mbsdiff %s %s %s", old_path, new_path, patch_path)
    command = [
        find_mbsdiff(),
        old_path,
        new_path,
        patch_path,
    ]
    subprocess.call(command)


def fix_permissions(ref_path, path):
    """Ensure permissions match the reference file."""
    log.debug("Fixing permissions on %s using reference file %s", path, ref_path)
    if os.access(ref_path, os.X_OK):
        path.chmod(0o755)
    else:
        path.chmod(0o644)


def check_for_forced_update(path, forced_list=None):
    """Check whether the file should be included regardless of diff."""
    if forced_list is None:
        forced_list = []

    # Always add these complete files.
    forced_file_list = [
        "precomplete",
        "Contents/Resources/precomplete",
        "removed-files",
        "Contents/Resources/removed-files",
        "Contents/CodeResources",
        "Contents/MacOS/firefox",
    ] + forced_list
    forced_file_list = [Path(p) for p in forced_file_list]
    if path in forced_file_list:
        return True
    if path.suffix == ".chk":
        return True
    return False


def check_for_add_if_not_update(path):
    """Check for files we should not overwrite."""
    exclusions = ["channel-prefs.js", "update-settings.ini"]
    return any([path.name == e for e in exclusions])


def is_extension(path):
    """Return True if the file is an extension.

    Extensions live in distribution/extensions/.*/
    """
    return path.match("distribution/extensions/**/*")


def extract_testdir(path):
    """Determine distribution path name.

    Extract everything up to and including the first subdirectory
    of distribution/extensions/../
    """
    if not is_extension(path):
        raise ValueError("Must be provided a path under distribution/extensions")
    return next(p for p in path.parents if p.match("distribution/extensions/*"))


def make_add_if_not_instruction(path):
    return 'add-if-not "{0}" "{0}"'.format(path)


def make_add_instruction(path):
    if is_extension(path):
        return 'add-if "{}" "{}"'.format(extract_testdir(path), path)
    else:
        return 'add "{}"'.format(path)


def make_patch_instruction(path):
    if is_extension(path):
        return 'patch-if "{0}" "{1}.patch" "{1}"'.format(extract_testdir(path), path)
    else:
        return 'patch "{0}.patch" "{0}"'.format(path)


def diff_files(
    work_dir, source_dir, target_dir, file_diffs, forced_file_list=None, bcj_arch=None
):

    directives = list()
    # Preserve ordering from earlier manifests.
    for path in sorted(file_diffs, reverse=True):
        log.info("Examining %s", path)
        old_path = source_dir / path
        new_path = target_dir / path
        work_path = work_dir / path

        if check_for_add_if_not_update(path):
            path.mkdir(parents=True, exist_ok=True)
            compress(new_path, work_path, bcj_arch=bcj_arch)
            fix_permissions(new_path, work_path)
            directives.append(make_add_if_not_instruction(path))
            continue

        if check_for_forced_update(path, forced_file_list):
            path.mkdir(parents=True, exist_ok=True)
            compress(new_path, work_path, bcj_arch=bcj_arch)
            fix_permissions(new_path, work_path)
            directives.append(make_add_instruction(path))
            continue

        if not cmp(old_path, new_path, shallow=False):
            work_path.parent.mkdir(parents=True, exist_ok=True)

            patch_path = work_path.parent / (work_path.name + ".patch")
            patch_xz_path = work_path.parent / (work_path.name + ".patch.xz")

            mbsdiff(old_path, new_path, patch_path)
            compress(new_path, work_path, bcj_arch=bcj_arch)
            fix_permissions(new_path, work_path)
            if patch_path.exists():
                compress(patch_path, patch_xz_path)  # no bcj options on patches.
                patch_path.unlink()
                # TODO Is there a way of estimating this without doing the
                # compression? Saves time
                # Mardor report on contents sizes? extract in two stages?

                # Depend on mardor here, is the first non-stdlib dependency. hm.
                # but m.mardata.index.entries has .size and .name
                # or binary mar -t marfile.
                if patch_xz_path.stat().st_size < work_path.stat().st_size:
                    directives.append(make_patch_instruction(path))
                    work_path.unlink()
                    patch_xz_path.rename(work_path)
                    continue

            # Fall through if mbsdiff failed, or the patch size was larger.
            directives.append(make_add_instruction(path))
            patch_xz_path.unlink()

    return directives


def add_new_files(work_dir, target_dir, additions, bcj_arch=None):
    directives = list()
    for path in additions:
        target_path = target_dir / path
        dest_path = work_dir / path
        compress(target_path, dest_path, bcj_arch=bcj_arch)
        fix_permissions(target_path, dest_path)
        if check_for_add_if_not_update(dest_path):
            directives.append(make_add_if_not_instruction(dest_path))
        else:
            directives.append(make_add_instruction(dest_path))

    return directives


def filepath_removals(removals):
    return ['remove "{}"'.format(r) for r in removals]


def directory_removals(removals):
    return ['rmdir "{}/"'.format(r.rstrip("/")) for r in removals]


def append_remove_instructions(target_dir):

    directives = list()
    list_file = target_dir / Path("removed-files")
    if not list_file.exists():
        list_file = target_dir / Path("Contents/Resources/removed-files")
    if not list_file.exists():
        return directives

    removal_files = list_file.read_text().splitlines()
    for removal in removal_files:
        if removal.lstrip(" ").startswith("#") or len(removal) == 0:
            continue
        if removal.endswith("/"):
            keyword = "rmdir"
        elif removal.endswith("/*"):
            keyword = "rmrfdir"
        else:
            keyword = "remove"
        directives.append('{} "{}"'.format(keyword, removal))

    return directives


def find_files(base_path, exclude=None):
    if not exclude:
        exclude = []
    return {
        p.relative_to(base_path)  # Remove name of base directory
        for p in base_path.glob("**/*")
        if p.is_file() and p.name not in exclude
    }


def find_dirs(base_path, exclude=None):
    if not exclude:
        exclude = []
    return {
        p.relative_to(base_path)  # Remove name of base directory
        for p in base_path.glob("**/*")
        if p.is_dir() and p.name not in exclude
    }


def make_incremental_update(
    source, target, patch_mar, channel_id=None, forced_file_list=None, bcj_arch=None
):
    if not channel_id:
        log.fatal(
            "MAR_CHANNEL_ID not specified, required in either environment or as an argument."
        )
        raise ValueError("MAR channel ID is required")

    # If we were given a MAR file, extract it
    source = Path(source)
    if source.is_file():
        source_dh = TemporaryDirectory()
        extract_mar(source, source_dh.name)
        source = Path(source_dh.name)

    target = Path(target)
    if target.is_file():
        # TODO This is also where we want to cache the file sizes for diff_files
        target_dh = TemporaryDirectory()
        extract_mar(target, target_dh.name)
        target = Path(target_dh.name)

    source_files = find_files(
        source, exclude=["updatev2.manifest", "updatev3.manifest"]
    )
    target_files = find_files(
        target, exclude=["updatev2.manifest", "updatev3.manifest"]
    )
    file_additions = target_files - source_files
    file_removals = source_files - target_files
    file_diffs = target_files.intersection(source_files)

    source_dirs = find_dirs(source)
    target_dirs = find_dirs(target)
    dir_removals = source_dirs - target_dirs

    with TemporaryDirectory() as work_dir:
        work_dir = Path("./dest")
        updatemanifestv3 = work_dir / Path("updatev3.manifest")

        directives = (
            ['type "partial"']
            + diff_files(work_dir, source, target, file_diffs, forced_file_list)
            + add_new_files(work_dir, target, file_additions, bcj_arch=bcj_arch)
            + filepath_removals(file_removals)
            + append_remove_instructions(target)
            + directory_removals(dir_removals)
        )

        updatemanifestv3.write_text("\n".join(directives))
        compress(updatemanifestv3, updatemanifestv3, bcj_arch=bcj_arch)
        log.info("Created manifest %s", updatemanifestv3)
        create_mar(work_dir, patch_mar, channel_id=channel_id)


def make_full_update(source, destination, channel_id=None, bcj_arch=None):
    """Create a MAR file from a given source directory."""
    if not channel_id:
        log.fatal(
            "MAR_CHANNEL_ID not specified, required in either environment or as an argument."
        )
        raise ValueError("MAR channel ID is required")

    source = Path(source)

    if not source.is_dir():
        log.fatal("%s is not a directory, unable to package as a MAR", source)
        raise ValueError("%s is not a directory", source)

    target_files = find_files(
        source, exclude=["updatev2.manifest", "updatev3.manifest"]
    )

    with TemporaryDirectory() as work_dir:
        updatemanifestv3 = work_dir / Path("updatev3.manifest")

        directives = (
            ['type "complete"']
            + add_new_files(work_dir, source, target_files, bcj_arch=bcj_arch)
            + append_remove_instructions(source)
        )
        updatemanifestv3.write_text("\n".join(directives))
        compress(updatemanifestv3, updatemanifestv3, bcj_arch=bcj_arch)
        log.info("Created manifest %s", updatemanifestv3)

        create_mar(work_dir, destination, channel_id=channel_id)


def make_full_update_wrapper(args):
    make_full_update(
        source=args.source_directory,
        destination=args.destination_mar,
        channel_id=args.mar_channel_id,
        bcj_arch=args.arch,
    )


def make_incremental_update_wrapper(args):
    make_incremental_update(
        source=args.source,
        target=args.target,
        patch_mar=args.patch_mar,
        forced_file_list=args.force_files,
        channel_id=args.mar_channel_id,
        bcj_arch=args.arch,
    )


def process_args():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help="sub-command help")

    parser_full = subparsers.add_parser("full", help="Make a full update MAR")
    parser_full.add_argument(
        "destination_mar", type=str, required=True, help="Destination MAR filename"
    )
    parser_full.add_argument(
        "source_directory", type=str, required=True, help="Destination MAR filename"
    )
    parser_full.add_argument(
        "--mar-channel-id",
        "--channel",
        type=str,
        help="MAR Channel ID to insert",
        default=os.environ.get("MAR_CHANNEL_ID"),
    )
    parser_full.add_argument(
        "--arch",
        type=str,
        required=True,
        choices=BCJ_OPTIONS.keys(),
        help="The archtecture you are building.",
    )
    parser_full.set_defaults(func=make_full_update_wrapper)

    parser_incr = subparsers.add_parser(
        "incremental", aliases=["incr"], help="Make a full update MAR"
    )
    parser_incr.add_argument(
        "patch_mar", type=str, required=True, help="Destination MAR filename"
    )
    parser_incr.add_argument(
        "source", type=str, required=True, help="'From' MAR or extracted directory"
    )
    parser_incr.add_argument(
        "target", type=str, required=True, help="'To' MAR or extracted directory"
    )
    parser_incr.add_argument(
        "-f",
        "--force-files",
        required=False,
        nargs="+",
        help="clobber this file in the installatiton.",
    )
    parser_incr.add_argument(
        "--mar-channel-id",
        "--channel",
        type=str,
        help="MAR Channel ID to insert",
        default=os.environ.get("MAR_CHANNEL_ID"),
    )
    parser_incr.add_argument(
        "--arch",
        type=str,
        required=True,
        choices=BCJ_OPTIONS.keys(),
        help="The archtecture you are building.",
    )

    parser_incr.set_defaults(func=make_incremental_update_wrapper)
    return parser.parse_args()


if __name__ == "__main__":
    args = process_args()
    args.func(args)
