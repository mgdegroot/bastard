#!/usr/bin/env python3
# Implements a pull-based synchronisation.
#
# TODO: Windows source environment
# TODO: Windows destination environment
# TODO: ignore / force filelist files process + testing
# TODO: file modify policy (updated files / new files in previously synced locations)
# TODO: different kinds of validation files
# TODO: realtime validatie synchronisatie data
#
#

import os
import datetime
import subprocess
import shelve
import json
import pprint
import hashlib
import logging
import argparse
import re
from enum import Enum
# TODO: get rid of these globals -->


class UserOptions:
    def __init__(self):
        self.DFLT_SRC_HOST = '192.168.42.10'
        self.DFLT_SRC_USER = 'backup'
        self.DFLT_SRC_PATH = '/media/storage/'
        self.DFLT_DST_PATH = '/media/storage/backup/'
        self.DFLT_LOGFILE = '/media/storage/meta/runner_backup.log'
        # self.DFLT_RSYNC_LOGFILE = 'rsync.log'
        self.DFLT_IFACE = 'ens33'
        self.DFLT_DATETIME_FORMAT = '%Y-%m-%dT%H%M%S'
        self.DFLT_SRC_SYNCSTATUS_FILE = '/media/storage/sync_status.txt'
        self.DFLT_VALIDATION_REMOTE_BASE = '/media/storage/Onderzoeken/'
        self.DFLT_VALIDATION_LOCAL_BASE = '/media/storage/validation/'
        self.DFLT_VALIDATION_TEMP = '/media/storage/validation/temp/'
        self.DFLT_METADATA_FILE = '/media/storage/meta/syncstat.json'
        # self.DFLT_EXCLUDES = [self.DFLT_SRC_SYNCSTATUS_FILE]
        self.DFLT_EXCLUDE_FILE = '/media/storage/meta/excludes.txt'
        self.DFLT_SYNC_REMOTE_LOG = '/media/storage/synchronization_{curr_datetime:%Y-%m-%dT%H%M}.log'
        self.DFLT_SYNC_LOCAL_LOG = '/media/storage/meta/synchronization_{curr_datetime:%Y-%m-%dT%H%M}.log'
        self.DFLT_INCLUDE_FILE = '/media/storage/meta/includes.txt'

        self.Dry_run = False
        self.Delete_with_sync = False
        self.Force = False
        self.Control_nic = False
        self.Interface = self.DFLT_IFACE
        self.Src_host = self.DFLT_SRC_HOST
        self.Src_username = self.DFLT_SRC_USER
        self.Src_path = self.DFLT_SRC_PATH
        self.Dst_path = self.DFLT_DST_PATH
        self.Logfile = self.DFLT_LOGFILE
        # self.Rsync_logfile = self.DFLT_RSYNC_LOGFILE.format(curr_datetime=datetime.datetime.now())
        self.Src_syncstatus_file = self.DFLT_SRC_SYNCSTATUS_FILE
        # self.Excludes = self.DFLT_EXCLUDES
        self.Exclude_file = self.DFLT_EXCLUDE_FILE
        self.Include_file = self.DFLT_INCLUDE_FILE
        self.Keep_remote_sync_log = True
        self.Sync_local_log = self.DFLT_SYNC_LOCAL_LOG.format(curr_datetime=datetime.datetime.now())
        self.Sync_remote_log = self.DFLT_SYNC_REMOTE_LOG.format(curr_datetime=datetime.datetime.now())
        self.Use_file_list = False
        self.Newer_than = None


# Global user options object (TODO: singleton access) -->
user_options = UserOptions()


class RuntimeEnvironment(Enum):
    LINUX = 1,
    WINDOWS = 2,
    DBG_WIN = 3,
    DBG_LIN = 4


class IFaceState(Enum):
    UP = 1,
    DOWN = 2



# The runtime environment (i.e.: operating system) -->
ENVIRONMENT = RuntimeEnvironment.LINUX

# The reference validation files -->
# TODO: verschillende soorten bestanden om selectieve malware ook te detecteren!1
VALIDATION_FILES = ['valfile1.txt', 'valfile2.txt', 'valfile3.txt', 'valfile4.txt', 'valfile5.txt']

MSG_SYNC_IN_PROGRESS = '{curr_datetime} - SYNC IS IN PROGRESS'
MSG_SYNC_DONE = '{curr_datetime} - SYNC COMPLETED'

if ENVIRONMENT == RuntimeEnvironment.LINUX:
    BIN_RSYNC = '/usr/bin/rsync'
    BIN_SSH = '/usr/bin/ssh'
    BIN_SCP = '/usr/bin/scp'
    BIN_EWFVERIFY = '/usr/bin/ewfverify'

# elif ENVIRONMENT == RuntimeEnvironment.WINDOWS:
#     raise NotImplemented('Windows prd not clear yet...')
#     BIN_IFACE_CTRL = 'netsh interface set interface "Wi-Fi 2" DISABLED'
# elif ENVIRONMENT == RuntimeEnvironment.DBG_WIN:
#     SYNC_SOURCE_PATH = 'D:\\opsec_nas\\sync_src\\'
#     SYNC_DEST_PATH = 'D:\\opsec_nas\\sync_dst\\'
#     METADATA_FILE = 'syncstat.json'
#     VALIDATION_REMOTE_BASE = 'D:\\opsec_nas\\'
#     VALIDATION_LOCAL_BASE = os.path.expanduser('D:\\opsec_nas\\')
#     VALIDATION_TEMP = 'D:\\opsec_nas\\temp\\'
#     REMOTE_STATUS_FILE = 'D:\\opsec_nas\\temp\\sync_status.txt'
# elif ENVIRONMENT == RuntimeEnvironment.DBG_LIN:
#     raise NotImplemented('Linux dbg not clear yet...')
#     BIN_RSYNC = '/usr/bin/rsync'
#     BIN_SSH = '/usr/bin/ssh'


def verify_ewf(filename):
    """
    Verify Expert Witness Format files.
    :param filename: 
    :return: 
    """
    params = [BIN_EWFVERIFY, filename]
    p_result = subprocess.run([*params], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if p_result.returncode != 0:
        stdout = stderr = ''
        if p_result.stdout is not None:
            stdout = str(p_result.stdout)
        if p_result.stderr is not None:
            stderr = str(p_result.stderr)

        msg = 'Failed to verify {filename}. STD output: {stdout}. ERR output: {stderr}'.format(filename=filename, stdout=stdout, stderr=stderr)
        logging.error(msg)

        return False
    else:
        return True


def walk_synced_files():
    """
    walk over all retrieved files, optionally perform actions on them.
    :return: 
    """
    if not os.path.exists(user_options.Sync_local_log):
        msg = 'rsync logfile {filename} not found.'.format(filename=user_options.Sync_local_log)
        logging.exception(msg)
        raise FileNotFoundError(msg)

    #     2017/03/10 10:40:59 [15642] >f+++++++++ Onderzoeken/valfile5.txt
    # r'^(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})\s\[(\d*)\]\s.*\s(.*/)(.*)$'
    # TODO: last line of rsync log matches regex but is no file...
    regex_line = re.compile(r'^(\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})\s\[(\d*)\]\s.*\s((.*/)(.*))$')

    with open(user_options.Sync_local_log, 'r') as f:
        loglines = f.readlines()

    for line in loglines:
		# TODO: fix regex so that this is no longer required -->
        if 'bytes/sec' in line:
            continue

        match = regex_line.match(line)
        if match is not None:
            try:
                synced_filename = match.group(5)
                if synced_filename != '':
                    synced_relative_path = match.group(3)
                    synced_dir_part = match.group(4)

                    synced_full_path = os.path.join(user_options.Dst_path, synced_relative_path)
                    test_file_integrity(synced_full_path)
            except Exception as e:
                msg = 'exception occured while parsing {line}: {ex_msg}'.format(line=line, ex_msg=str(e))
                logging.exception(msg)


def test_file_integrity(filename: str):
    """
    Verify file based on extension
    TODO: Extend to enable explicit filetype passing and detection using magic values.
    :param filename: The filename to test
    :return: True when the file seems to be corrct, False otherwise.
    """
    filename = os.path.expanduser(filename)
    if not os.path.exists(filename):
        msg = 'File {filename} not found.'.format(filename=filename)
        logging.exception(msg)
        # raise FileNotFoundError(msg)

    namepart, extension = os.path.splitext(filename)
    # fix potential case confusion -->
    extension = extension.upper()

    if extension == '.E01':
        verify_ewf(filename)
    else:
        msg = 'No integrity checking for .{ext} files yet...'.format(ext=extension)
        logging.warning(msg)
        # raise NotImplementedError(msg)


def write_metadata(metadata: dict):
    """
    Serialize metadata to file
    :param metadata:
    :return:
    """

    # TODO: any advantage to using shelve module instead of json -->
    # shelve_db = shelve.open('runner_backup.shelve')
    # shelve_db['metadata'] = metadata

    metadata['syncdatetime'] = '{:%Y-%m-%dT%H%M%S}'.format(metadata['syncdatetime'])
    metadata['prev_syncdatetime'] = '{:%Y-%m-%dT%H%M%S}'.format(metadata['prev_syncdatetime'])
    # metadata = {
    #     'id': 'data_sync',
    #     'version': version,
    #     'syncdatetime': '{:%Y-%m-%dT%H%M%S}'.format(datetime.datetime.now()),
    #     'syncresult': result,
    #     'prev_syncdatetime': '{:%Y-%m-%dT%H%M%S}'.format(prev_syncdatetime),
    #     'prev_syncresult': True
    # }

    with open(user_options.DFLT_METADATA_FILE, 'w') as metafile:
        json.dump(metadata, metafile)

    logging.info('local metadata ({metafile}) file updated'.format(metafile=user_options.DFLT_METADATA_FILE))


def read_metadata(filename:str, interactive=True):
    """
    Create metadata dictionary with values from file. If it does not exist the user is asked whether a new
    one should be created. If not an exception is raised.
    :param filename: The file to use as source.
    :param interactive: Whether or not to ask for user input in case file not found.
    :return: The created metadata dictionary.
    """

    # TODO: any advantage to using shelve module instead of json -->
    # shelve_db = shelve.open('runner_backup.shelve')
    # metadata = shelve_db['metadata']
    # return metadata

    if not os.path.exists(filename):
        do_create = input('Metadata file not found. Create new one (y/n)?')
        if do_create == 'y':
            metadata = {
                'id': 'data_sync',
                'version': 1,
                'syncdatetime': '1700-01-01T000000',
                'syncresult': 'false',
                'prev_syncdatetime': '1700-01-01T000000',
                'prev_syncresult': 'false',
                'msg': ''
            }
            logging.info('Creating new metadata file {filename} with contents {metadata}'.format(
                filename=filename,
                metadata=pprint.pformat(metadata)
            ))
        else:
            msg = 'Metadata bestand niet gevonden: {}'.format(filename)
            logging.exception(msg)
            raise FileNotFoundError(msg)
    else:
        with open(filename, 'r') as metafile:
            metadata = json.load(metafile)
    # datetime.datetime.strptime(str_timestamp, '%Y-%m-%dT%H:%M:%SZ')
    metadata['syncdatetime'] = datetime.datetime.strptime(metadata['syncdatetime'],'%Y-%m-%dT%H%M%S')
    metadata['prev_syncdatetime'] = datetime.datetime.strptime(metadata['prev_syncdatetime'], '%Y-%m-%dT%H%M%S')
    logging.debug('metadata file {filename} loaded. Contents is: {metadata}'.format(
        filename=filename,
        metadata=pprint.pformat(metadata)
    ))

    return metadata


def update_metadata(metadata: dict, new_result: bool, msg: str):
    """
    Update the metadata structure with new values.
    :param metadata: The dictionary to update.
    :param new_result: The result to set.
    :param msg: A message to set.
    :return:
    """

    metadata['prev_syncdatetime'] = metadata['syncdatetime']
    metadata['prev_syncresult'] = metadata['syncresult']
    metadata['syncdatetime'] = datetime.datetime.now()
    metadata['syncresult'] = new_result
    metadata['version'] += 1
    metadata['msg'] = msg

    logging.debug('metadata structure updated. New values: {}'.format(pprint.pformat(metadata)))

    # return metadata


def put_remote_status_file(remote_filename:str, message:str):
    """
    Put a file <remote_filename> containing the tekst <message>.
    :param remote_filename: The full path on the remote host
    :param message: The tekst to put in the file.
    :return:
    """

    logging.debug('putting remote status file {remote_filename} on {remote_host}'.format(
        remote_filename=remote_filename,
        remote_host=user_options.Src_host)
    )

    res = subprocess.run(
        [
            BIN_SSH,
            '-t',
            '{user}@{host}'.format(user=user_options.Src_username, host=user_options.Src_host),
            'echo',
            message,
            '>',
            remote_filename
         ])
    if res.returncode == 0:
        logging.info('successfully updated status file {remote_filename} on {remote_host}'.format(
            remote_filename=remote_filename, remote_host=user_options.Src_host)
        )
    else:
        logging.error('got error trying to update status file {remote_filename} on {remote_host}'.format(
            remote_filename=remote_filename, remote_host=user_options.Src_host)
        )


def write_reference_validation_hashes(base_path:str, reference_files:list):
    """
    Calculate the sha256 hash for the reference_files under base_path.
    :param base_path: The directory containing the reference files
    :param reference_files: List containing the reference files.
    :return:
    """
    if not os.path.exists(base_path):
        msg = 'Validation directory {} not found'.format(base_path)
        logging.exception(msg)
        raise FileNotFoundError(msg)

    for filename in reference_files:
        local_full_path = os.path.join(base_path, filename)
        if not os.path.exists(local_full_path):
            msg = 'Validation file {} not found'.format(local_full_path)
            logging.exception(msg)
            raise FileNotFoundError(msg)

        sha256_digest = get_sha256_hexdigest(local_full_path)
        logging.debug('sha256 digest for {filename} is {digest}'.format(filename=local_full_path, digest=sha256_digest))
        local_hash_full_path = local_full_path + '.sha256'
        with open(local_hash_full_path, 'w') as hashfile:
            hashfile.write(sha256_digest)
            logging.debug('sha256 written to file {filename}'.format(filename=local_hash_full_path))


def get_sha256_hexdigest(full_path):
    """
    Calculate and return the sha256 digest for a file.
    :param full_path: The file to compute the digest for.
    :return: The calculated digest.
    """
    sha256 = hashlib.sha256()
    with open(full_path, 'rb') as f:
        while True:
            buf = f.read(2 ** 20)
            if not buf:
                break
            sha256.update(buf)
    sha256 = sha256.hexdigest()
    return sha256


def put_reference_validation_files():
    """
    Put the reference files on the source device to serve as validation for a later sync run.
    :return:
    """

    if not os.path.exists(user_options.DFLT_VALIDATION_LOCAL_BASE):
        raise FileNotFoundError('Validation directory {} not found'.format(user_options.DFLT_VALIDATION_LOCAL_BASE))

    for filename in VALIDATION_FILES:
        local_full_path = os.path.join(user_options.DFLT_VALIDATION_LOCAL_BASE, filename)
        if not os.path.exists(local_full_path):
            raise FileNotFoundError('Validation file {} not found'.format(local_full_path))

        p_result = subprocess.run([
            BIN_SCP,
            local_full_path,
            '{user}@{host}:{remote_loc}'.format(
                user=user_options.Src_username,
                host=user_options.Src_host,
                remote_loc=user_options.DFLT_VALIDATION_REMOTE_BASE
            )
        ])

        if p_result.returncode != 0 and p_result.returncode != 42:
            msg = 'Non-zero return code (en niet eens 42...)'
            logging.exception(msg)
            raise ValueError(msg)
        elif p_result.returncode == 42:
            msg = '{:d}...How about that...'.format(p_result.returncode)
            logging.exception(msg)
            raise ValueError(msg)
        else:
            logging.info('Reference file {ref_file} put on {remote_host} under {remote_file}'.format(
                ref_file=filename,
                remote_host=user_options.Src_host,
                remote_file=user_options.DFLT_VALIDATION_REMOTE_BASE
            ))


def get_remote_validation_files(remote_base_path:str, validation_files:list):
    """
    Collect the remote validation files and store them in the validation temp folder.
    :param remote_base_path:
    :param validation_files:
    :return:
    """
    for filename in validation_files:
        full_remote_path = os.path.join(remote_base_path, filename)
        subprocess.run([
            BIN_SCP,
            '{user}@{host}:{remote_loc}'.format(
                user=user_options.Src_username,
                host=user_options.Src_host,
                remote_loc=full_remote_path
            ),
            user_options.DFLT_VALIDATION_TEMP
        ])


def validate_source_integrity(hash_reference_files:bool=False):
    """
    Fetch remote files and validate whether the hashes match the pre-computed hashes.
    When failed raise an exception.
    :param hash_reference_files: Whether or not to compute the hashes of the locally stored validation files.
    :return:
    """
    # Collect remote 'live' files -->
    get_remote_validation_files(remote_base_path=user_options.DFLT_VALIDATION_REMOTE_BASE, validation_files=VALIDATION_FILES)

    # If specified first generate hashes of the reference files -->
    if hash_reference_files:
        write_reference_validation_hashes(user_options.DFLT_VALIDATION_LOCAL_BASE, reference_files=VALIDATION_FILES)

    # Validate live files against reference files -->
    for filename in VALIDATION_FILES:
        reference_local_full_path = os.path.join(user_options.DFLT_VALIDATION_LOCAL_BASE, filename)
        reference_local_hash_full_path = os.path.join(user_options.DFLT_VALIDATION_LOCAL_BASE, filename) + '.sha256'

        if not os.path.exists(reference_local_hash_full_path):
            raise FileNotFoundError('Reference hashfile {} not found...'.format(reference_local_hash_full_path))

        # Get the reference hash -->
        with open(reference_local_hash_full_path, 'r') as hash_file:
            ref_hash = hash_file.read()

        if ref_hash == '':
            raise ValueError('Invalid hash in file {}'.format(reference_local_hash_full_path))

        live_full_path = os.path.join(user_options.DFLT_VALIDATION_TEMP, filename)
        if not os.path.exists(live_full_path):
            raise FileNotFoundError('Live file {} not found..'.format(live_full_path))

        # Get the validation file hash -->
        live_hash = get_sha256_hexdigest(live_full_path)

        # PANIC PANIC PANIC -->
        if live_hash != ref_hash:
            # TODO: raise exception or return False? exception is probably better here...
            msg = 'INTEGRITY FAIL on {filename}. Verify manually before sync. Stopping process. Rerun when corrected!'.format(filename=filename)
            logging.exception(msg)
            raise ValueError(msg)
        else:
            logging.info('SUCCESS: Hash of live file \'{live_file}\' matches reference \'{reference_file}\':\n{ref_hash}\n{live_hash}'.format(
                live_file=live_full_path,
                reference_file=reference_local_full_path,
                ref_hash=ref_hash,
                live_hash=live_hash
            ))
    # If we got through to here validation is successful -->
    logging.info('Validation success: Reference files match validation files')
    return True


def exec_rsync():
    """
    Perform the rsync. In case of error an exception is thrown.
    TODO: more granular error handling.
    :return:
    """

    # /usr/bin/rsync -a --delete -e ssh backup@192.168.42.10:/media/storage/ /media/storage/backup/
    if not os.path.exists(user_options.Dst_path):
        msg = 'Sync destination {} not found.'.format(user_options.Dst_path)
        logging.exception(msg)
        raise FileNotFoundError(msg)

    rsync_params = [
        BIN_RSYNC,
        '--log-file={}'.format(user_options.Sync_local_log),
        '-av',
        '-e',
        'ssh',
        '--exclude-from={exclude_file}'.format(exclude_file=user_options.Exclude_file)
    ]

    if user_options.Delete_with_sync:
        rsync_params.append('--delete')

    if user_options.Keep_remote_sync_log:
        rsync_params.append('--remote-option')
        rsync_params.append('--log-file={}'.format(user_options.Sync_remote_log))

    if user_options.Include_file:
        rsync_params.append('--include-from={include_file}'.format(include_file=user_options.Include_file))

    rsync_params.append('{user}@{host}:{sync_source}'.format(
        user=user_options.Src_username,
        host=user_options.Src_host,
        sync_source=user_options.Src_path
    ))
    rsync_params.append(user_options.Dst_path)

    # --exclude=rsync_status
    # --exclude-from=<exclude file>
    # --remote-option --log-file=
    logging.debug('Executing rsync. Parameters: {sync_params}'.format(sync_params=pprint.pformat(rsync_params)))
    p_result = subprocess.run([*rsync_params], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if p_result.stdout is not None:
        stdout = str(p_result.stdout)
        logging.info('Rsync output: {rsync_output}'.format(rsync_output=stdout))

    if p_result.returncode != 0:
        stderr = str(p_result.stderr)
        msg = 'rsync returned non-zero: {returncode:d}. STDERR: {stderr}'.format(returncode=p_result.returncode, stderr=stderr)
        logging.exception(msg)
        raise RuntimeError(msg)

    return True


def control_netinterface(new_state:IFaceState):
    """
    Control the state of the network interface. Requires sudo access.
    :param new_state: One of IFaceSate.UP or .DOWN
    :return: True on success, False otherwise.
    """
    p_result = None
    if new_state == IFaceState.UP:
        p_result = subprocess.run(['sudo', 'ip', 'link', 'set', user_options.Interface, 'up'])
    elif new_state == IFaceState.DOWN:
        p_result = subprocess.run(['sudo', 'ip', 'link', 'set', user_options.Interface, 'down'])

    logging.info('interface {interface} set to state {state}'.format(interface=user_options.Interface, state=new_state.name))
    if p_result is not None and p_result.returncode == 0:
        return True
    else:
        return False


def get_sync_filelist():
    if user_options.Use_file_list is True and user_options.Newer_than is not None:
        print('getting filenames...')
        cmd_find = 'find {search_loc} -newermt "{date_newerthan}" -type f'.format(
            search_loc=user_options.Src_path,
            date_newerthan=user_options.Newer_than.strftime("%Y%m%d")
        )

        p_result = subprocess.run(
            [
                BIN_SSH,
                '{user}@{host}'.format(user=user_options.Src_username, host=user_options.Src_host),
                cmd_find
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        if p_result is not None and p_result.returncode == 0:

            stdout = str(p_result.stdout)
            with open(user_options.Include_file, 'w') as include_file:
                include_file.write(stdout)
                # include_file.writelines(stdout.splitlines())


    else:
        print('nope')

#         find <loc> -type f -newermt "<yyyyMMdd>"


def cleanup():
    if user_options.Newer_than is not None and os.path.exists(user_options.Include_file):
        os.remove(user_options.Include_file)



def parse_args():
    global user_options

    parser = argparse.ArgumentParser()

    parser.add_argument('--src_host', default=user_options.DFLT_SRC_HOST, type=str,
                        help='The hostname or ip address of the source (origin).')
    parser.add_argument('--src_username', default=user_options.DFLT_SRC_USER, type=str,
                        help='The username for the source (origin) host.')
    parser.add_argument('--src-path', dest='src_path', default=user_options.DFLT_SRC_PATH, type=str,
                        help='The path on the source (origin) host.')
    parser.add_argument('--dst-path', dest='dst_path', default=user_options.DFLT_DST_PATH, type=str,
                        help='The path on the destination host.')
    parser.add_argument('--exclude-file', dest='exclude_file', default=None, type=str,
                        help='Path to file containing filepatterns to ignore (exclude) when syncing.')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Force updating of existing files.')
    parser.add_argument('--delete', action='store_true', default=False,
                        help='Also delete files in destination when syncing.')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true', default=False,
                        help='Simulate, don\'t touch anything except logfile.')
    parser.add_argument('--control-nic', dest='control_nic', action='store_true', default=False,
                        help='Control the network interface state.')
    parser.add_argument('--interface', default=None, type=str,
                        help='The interface to use when \'--control-nic\' option is used.')
    parser.add_argument('--remote-rsync-log', dest='remote_rsync_log', default=None, type=str,
                        help='The path on the source system to keep the rsync log. If not specified it is not created.')
    parser.add_argument('--newer-than', dest='newer_than', default=None, type=str,
                        help='Only sync files and directories newer then <yyyy-MM-dd hh:mm>')

    args = parser.parse_args()

    if args.src_host:
        user_options.Src_host = args.src_host
    if args.src_username:
        user_options.Src_username = args.src_username
    if args.src_path:
        user_options.Src_path = args.src_path
    if args.dst_path:
        user_options.Dst_path = args.dst_path
    if args.exclude_file:
        user_options.Exclude_file = args.exclude_file
    if args.force:
        user_options.Force = args.force
    if args.delete:
        user_options.Delete_with_sync = args.delete
    if args.dry_run:
        user_options.Dry_run = args.dry_run
    if args.control_nic:
        user_options.Control_nic = args.control_nic
    if args.interface:
        if not args.control_nic:
            msg = 'parameter \'--interface\' is only useful with \'--control-nic\''
            logging.exception(msg)
            raise RuntimeError(msg)
        user_options.Interface = args.interface
    if args.remote_rsync_log:
        user_options.Keep_remote_sync_log = True
        user_options.Sync_remote_log = args.remote_rsync_log
    if args.newer_than:
        user_options.Use_file_list = True

        try:
            newerThanDate = datetime.datetime.strptime(args.newer_than, "%Y-%m-%d")
            user_options.Newer_than = newerThanDate
        except Exception as ex:
            print('err: {}'.format(ex))
            exit(1)

    return user_options


def init_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(' %(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(filename=user_options.Logfile)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(' %(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    logger.addHandler(file_handler)


if __name__ == '__main__':
    # Get user options -->
    parse_args()

    get_sync_filelist()

    exit(0)
    # log_format = format=' %(asctime)s - %(levelname)s - %(funcName)s - %(message)s'
    #
    # logging.getLogger().addHandler(logging.StreamHandler())
    # logging.getLogger().addHandler(logging.FileHandler(filename=user_options.Logfile))
    # logging.basicConfig(
    #     filename=user_options.Logfile,
    #     level=logging.INFO,
    #     format=' %(asctime)s - %(levelname)s - %(funcName)s - %(message)s'
    # )
    init_logger()

    logging.info('Starting sync run.')

    # If configured set the correct NIC state -->
    if user_options.Control_nic:
        control_netinterface(IFaceState.UP)

    # Read info from previous run -->
    metadata = read_metadata(user_options.DFLT_METADATA_FILE, interactive=True)

    print('''
    Previous run:
    \tVersion: {version}
    \tDate: {date}
    \tResult: {result}
    '''.format(version=metadata['version'],
               date=metadata['syncdatetime'],
               result=metadata['syncresult']
        )
    )

    print('''
    Using values:
    \tsrc host: {src_host}
    \tsrc username: {src_username}
    \tsrc path: {src_path}
    \tdelete with sync: {delete}
    \tforce: {force}
    '''.format(src_host=user_options.Src_host,
               src_username=user_options.Src_username,
               src_path=user_options.Src_path,
               delete=user_options.Delete_with_sync,
               force=user_options.Force
        )
    )

    # Validate whether source is usable (link and content) -->
    validate_result = validate_source_integrity(hash_reference_files=False)

    if not validate_result:
        update_metadata(metadata, False, 'Validation failed.')
        write_metadata(metadata)
        exit(1)

    # Inform remote system that a sync is in progress -->
    put_remote_status_file(
        remote_filename=user_options.Src_syncstatus_file,
        message=MSG_SYNC_IN_PROGRESS.format(curr_datetime=datetime.datetime.now())
    )

    # Execute the synchronisation -->
    rsync_result = exec_rsync()

    # Remove 'sync in progress' message file -->
    put_remote_status_file(
        remote_filename=user_options.Src_syncstatus_file,
        message=MSG_SYNC_DONE.format(curr_datetime=datetime.datetime.now())
    )

    if not rsync_result:
        update_metadata(metadata, False, 'RSync failed.')
        write_metadata(metadata)
        exit(1)

    walk_synced_files()

    # Serialize the result of this run to disk -->
    update_metadata(metadata, True, 'Success.')
    write_metadata(metadata)

    # If configured set the correct NIC state -->
    if user_options.Control_nic:
        control_netinterface(IFaceState.DOWN)

    exit(0)
