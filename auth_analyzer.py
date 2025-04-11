import re
import sys
import textwrap
import time
import threading

# Constants
DEFAULT_MENU_COLOR = 34
DEFAULT_REPORT_WIDTH = 150
ERROR_COLOR_CODE = 31
DEFAULT_AUTHLOG_PATH = r"/var/log/auth.log"
EXCLUDE_INSIGNIFICANT_LOG_ENTRIES = True

# Global variables
auth_log_path = ''
stop_monitoring = False  # Global flag to control monitoring

# Event types that are included during the analysis of the log file
important_event_types = (
    'invalid-user',
    'max-authentication-attempts-exceeded',
    'failed-login',
    'successful-login',
    'successful-su',
    'sudo-auth-failure',
    'sudo-command',
    'user-created',
    'user-deleted',
    'group-created',
    'password-change',
    'session-opened',
    "session-closed",
    'chpasswd-non-existing-user'
)

# All event types that are currently supported for parsing
event_patterns = {
    "user-created": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+new user: name=(?P<username>\S+), UID=(?P<user_id>\d+)',
    "password-change": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+pam_unix\((?P<service>\S+):(?P<pam_activity>\S+)\):\s+password changed for (?P<username>\S+)',
    "new-connection": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Connection from (?P<src_ip_address>[\d.]+) port (?P<src_port>\d+) on (?P<dst_ip_address>[\d.]+) port (?P<dst_port>\d+)',
    "connection-reset": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Connection reset by (?P<ip_address>[\d.]+) port (?P<port>\d+)',
    "invalid-user": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Invalid user (?P<username>\S+)?( from (?P<ip_address>[\d.]+)( port (?P<port>\d+))?)?',
    "successful-login": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?: Accepted (?P<auth_method>\w+) for (?P<username>\S+) from (?P<ip_address>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)(: )?(?P<ssh_signature>RSA SHA256:[A-Za-z0-9+/=]+)?',
    "failed-login": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Failed (?P<auth_method>\w+) for (invalid )?(user )?(?P<username>\S+)? from (?P<ip_address>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)(: )?(RSA SHA256:[A-Za-z0-9+/=]+)?',
    "max-authentication-attempts-exceeded": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+error\: maximum authentication attempts exceeded for (invalid user )?(?P<username>\S+) from (?P<ip_address>[\d.]+) port (?P<port>\d+) (?P<protocol>\w+)',
    "disconnect-user0": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2}) (?P<hostname>[\w\-]+) (?P<process>\S+)(\[(?P<pid>\d+)\])?: ((Disconnected from)|Disconnecting) (invalid |authenticating )?(user (?P<username>\S+) )?(?P<ip_address>[\d.]+) port (?P<port>\d+)(:.*)?',
    "disconnect-user1": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Received disconnect from (?P<ip_address>[\d.]+)(?: port (?P<port>\d+))?:(?P<error_code>\d+):.*\[(?P<stage>\w+)\]',
    "disconnect-user": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+Disconnected from (invalid |authenticating )?user (?P<username>\S+) (?P<ip_address>[\d.]+) port (?P<port>\d+) \[(?P<stage>\w+)\]',
    "new-session": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+New session \d+ of user (?P<username>\S+)',
    "session-opened": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?: pam_unix\((?P<service>\S+):(?P<pam_activity>\S+)\): session opened for user (?P<sudo_user>\S+) by (?P<username>\S+)?\(uid=(?P<user_id>\d+)\)',
    "session-closed": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?: pam_unix\((?P<service>\S+):(?P<pam_activity>\S+)\): session closed for user (?P<sudo_user>\S+)',
    "successful-su": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?: Successful su for (?P<sudo_user>\S+) by (?P<username>\S+)',
    "sudo-command": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+(?P<username>\S+) : ((?P<error>.*?) ; )?(TTY=(?P<tty>\S+) ; )?PWD=(?P<pwd>\S+) ; USER=(?P<sudo_user>\S+) ;( COMMAND=(?P<command>.+))?',
    "sudo-auth-failure": r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+pam_unix\((?P<service>\S+):(?P<pam_activity>\S+)\): authentication failure; ?logname=(?P<logname>.*?) ?uid=(?P<uid>\d+) ?euid=(?P<euid>\d+) ?tty=(?P<tty>\S+) ?ruser=(?P<ruser>.*?) ?rhost=(?P<rhost>.*?)( user=(?P<user>\w+))?',
    "failed-adding-user": r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+failed adding user \'(?P<username>\S+)\'",
    'group-added-to': r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+group added to (?P<target>\S+): name=(?P<group>\S+)',
    'group-created': r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+new group: name=(?P<group>\S+)',
    'chpasswd-non-existing-user': r'^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+pam_unix\((?P<service>\S+):(?P<pam_activity>\S+)\): user \"(?P<username>\S+)\" does not exist in /etc/passwd',
    'user-deleted': r"^(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w\-]+)\s+(?P<process>\S+)(\[(?P<pid>\d+)\])?:\s+(delete|remove|removed) user '(?P<username>\S+)'"
}

# Patterns that I decided to be unnecessary to process after testing the script with large log files
# In most cases there is another pattern that is associated with the same event
patterns_to_be_ignored = (
    'Removed session',
    'Cannot create session: Already running in a session',
    'Disconnecting: Too many authentication failures',
    'ignoring max retries',
    'check pass; user unknown',
    'more authentication failures',
    'Bad protocol version identification',
    'Connection closed by',
    'Closing connection',
    'Connection reset',
    'Unable to negotiate with',
    'Did not receive identification string',
    'Received disconnect from',
    'input_userauth_request: invalid user',
    '/dev/pts/0 root:root',
    'Server listening on',
    'User child is on pid',
    'Starting session:',
    'Close session:',
    'message repeated',
    'Waiting for processes to exit',
    'banner exchange',
    'Postponed publickey for',
    'Could not set limit for',
    'Connection reset by peer',
    'banner line contains invalid characters',
    'Accepted key',
    'more authentication failure'
)

# Containers for extracted data from the log after parsing.
# They are stored in momory and provide fast and convenient access to all extracted information
saved_events = []
events_by_username = {}

# Container for the report output
report_data = {}


# Utility to print colored text in the terminal
def color(text, color_code=0):
    return f"\033[{color_code}m{text}\033[0m"


# Utility to print text limited to a specified width
def wrap(text):
    print(textwrap.fill(str(text), width=DEFAULT_REPORT_WIDTH))


# Print application banner
def print_banner():
    app_name = "Auth.log Recon v1.0"
    tagline = "👁️ Unveiling Hidden Threats in Authentication Logs 🕵️"
    developer = "Developed by: Radostin Tonev"
    github = "Github: https://github.com/radtonev/auth_analyzer"
    email = "Email: radtonev@gmail.com"
    license_info = "License: MIT"

    top_border = color("".join(['*' if i % 2 == 0 else '#' for i in range(60)]), "31;1")  # --- Top Jagged Border ---
    app_line = f"            >>>  {color(app_name, '36;1')}  <<<"  # --- Application Name with Emphasis ---
    colored_tagline = color(f"    {tagline}", "33")  # --- Tagline with Visual Break ---
    separator = color("-" * 60, "34")  # --- Separator Line ---

    # --- Author Information ---
    colored_developer = color(f"{developer}", "37")
    colored_github = color(f"{github}", "37")
    colored_email = color(f"{email}", "37")
    colored_license_info = color(f"{license_info}", "37")

    bottom_border = color("".join(['#' if i % 2 == 0 else '*' for i in range(60)]),
                          "31;1")  # --- Bottom Jagged Border ---

    banner = [
        top_border.center(60),
        "",
        app_line.center(60),
        colored_tagline.center(60),
        separator.center(60),
        "",
        colored_developer.rjust(49),
        colored_github.rjust(70),
        colored_email.rjust(46),
        colored_license_info.rjust(33),
        "",
        bottom_border.center(60),
        ""
    ]

    for line in banner:
        print(line)


# Displays and updates progress bar on a single line
def show_progress_bar(total, current):
    percentage = int((current * 100) / float(total))
    fill = "▓"
    empty = "░"
    bar_color = '\033[32m'
    end_color = '\033[0m'

    filled_length = int(100 * current // total)
    bar = fill * filled_length + empty * (100 - filled_length)
    sys.stdout.write(f'\r|{bar_color}{bar}{end_color}| {percentage}%')
    sys.stdout.flush()


# Reads auth log file from user input
def read_authlog_path():
    prompt = f"Please enter the path to the auth.log file you wish to investigate.\nFor default location [ {DEFAULT_AUTHLOG_PATH} ] just press \033[34mENTER\033[0m: "
    path = input(prompt).strip()
    if not path:
        path = DEFAULT_AUTHLOG_PATH
    print()
    return path


# Checks if current line should be excluded from parsing
def line_should_be_ignored(line):
    for pattern in patterns_to_be_ignored:
        if pattern in line:
            return True
    return False


# Match the log record to a specific event type
def extract_data(line, line_number=0):
    data = {}
    for event_type in event_patterns.keys():
        match = re.search(event_patterns.get(event_type), line)
        if match:
            data = {
                "event_type": event_type,
                "line_number": line_number,
                "event_details": match.groupdict()
            }
            break
    return data


# Process log file line by line and fill saved_events list with data
def parse_log_file():
    print("Processing ...")
    try:
        with open(auth_log_path, "r", encoding='utf-8') as log:
            total_events = sum(1 for _ in log)
            log.seek(0)  # Reset cursor to beginning
            undetected_events_count = 0
            line_number = 0
            for line in log:
                line_number += 1
                ignore_line = line_should_be_ignored(line)
                if not ignore_line:
                    data = extract_data(line, line_number)
                    if not data:
                        undetected_events_count += 1
                        continue
                    if data.get('event_type') in important_event_types:
                        saved_events.append(data)
                show_progress_bar(total_events, line_number)

        fill_events_by_username()  # Put the extracted data in a different more convenient format
        processed_records_percentage = (100 * float(total_events - undetected_events_count) / float(total_events))
        if processed_records_percentage < 100:
            print(
                f"\nFinished parsing the log.\nThe script managed to recognize and extract data from \033[31m{processed_records_percentage:.2f}%\033[0m of the log records as known parsable format.")
            print(f"{len(saved_events)} interesting events were found.")
            q = input("Do you wish to proceed with log analysis [ \033[34mENTER\033[0m / q => quit ]? ")
            if q.strip() == "q":
                print("Exiting ...")
                exit(0)
    except FileNotFoundError:
        print(color("Error: File not found. Please re-run the script and provide proper file path.", '31;1'))
        print("Exiting ...")
        exit(-1)
    except Exception as e:
        print(color(f"Unhandled error: {e}", '31;1'))
        print("Exiting ...")
        exit(-1)


# Put the extracted events in chronological order for each user and fills events_by_username dictionary
def fill_events_by_username():
    global events_by_username

    users_events = {}
    sorted_users_events = {}

    for event in saved_events:
        details = event.get('event_details')
        username = details.get('username')
        if username:
            if not (username in users_events.keys()):
                users_events[username] = []
            users_events[username].append({
                "line_number": event.get('line_number'),
                "event_type": event.get('event_type'),
                "event": details
            })

    for username in users_events:
        sorted_events = sorted(users_events[username], key=lambda event: event.get("line_number"))
        sorted_users_events[username] = sorted_events

    events_by_username = sorted_users_events


# Performs analysis on the parsed data and fills report_data with relevant information
def analyze_log_file():
    print('\nProcessing ... It won\'t take long.')

    report_data['processes'] = get_processes()

    new_users, deleted_users, password_changes, new_groups = get_user_manipulations()
    report_data['created_users'] = new_users
    report_data['deleted_users'] = deleted_users
    report_data['created_groups'] = new_groups
    report_data['password_changes'] = password_changes

    successful_logins, failed_logins = get_logins()
    report_data['successful_logins'] = successful_logins
    report_data['failed_logins'] = failed_logins

    report_data['invalid_usernames'] = get_invalid_usernames()

    sudoers, failed_sudo_users, failed_sudo_events = get_sudoers()
    report_data['sudoers'] = sudoers
    report_data['failed_sudo_users'] = failed_sudo_users
    report_data['failed_sudo_events'] = failed_sudo_events

    report_data['su_usages'] = get_su_usages()
    print("All done!")


# Gets all unique processes in the context
def get_processes():
    processes = []
    for event in saved_events:
        process = event.get('event_details').get('process')
        if process:
            if process.find('[') != -1:
                process = process[:process.find('[')]
            if process not in processes:
                processes.append(process)
    return processes


# Gets user manipulation events
def get_user_manipulations():
    new_users = []
    deleted_users = []
    new_groups = []
    password_changes = []

    for event in saved_events:
        if event.get('event_type') == 'user-created':
            username = event.get('event_details').get('username')
            if username not in new_users:
                new_users.append(username)
        elif event.get('event_type') == 'group-created':
            group = event.get('event_details').get('group')
            if group not in new_groups:
                new_groups.append(group)
        elif event.get('event_type') == 'user-deleted':
            username = event.get('event_details').get('username')
            if username not in deleted_users:
                deleted_users.append(username)
        elif event.get('event_type') == 'password-change':
            username = event.get('event_details').get('username')
            if username not in password_changes:
                password_changes.append(username)

    return new_users, deleted_users, password_changes, new_groups


# Gets login information for all users and returns it in displayable format
def get_logins():
    logged_users = []
    failed_users = []
    logged_users_display = []
    failed_users_display = []

    for username in events_by_username.keys():
        for event in events_by_username[username]:
            if event.get('event_type') == 'failed-login':
                if username not in failed_users:
                    failed_users.append(username)
                    failed_users_display.append(username + " (" + str(len(events_by_username[username])) + ")")
            elif event.get('event_type') == 'successful-login':
                if username not in logged_users:
                    logged_users.append(username)
                    logged_users_display.append(username + " (" + str(len(events_by_username[username])) + ")")
    return logged_users_display, failed_users_display


# Gets all invalid usernames
def get_invalid_usernames():
    users = []
    for event in saved_events:
        if event.get('event_type') == 'invalid-user':
            username = event.get('event_details').get('username')
            if username not in users:
                users.append(username)
    return users


# Gets all users that either used or attempted to use the sudo command
def get_sudoers():
    users = []
    failed_sudo_users = []
    failed_sudo_events = []

    for username in events_by_username.keys():
        events = events_by_username[username]
        for event in events:
            if event.get('event_type') == 'sudo-command':
                if username not in users:
                    users.append(username)
            elif event.get('event_type') == 'auth-failure':
                if event.get('event').get('process') == 'sudo':
                    failed_sudo_events.append(event)
                    username = event.get('ruser')
                    if username not in failed_sudo_users:
                        failed_sudo_users.append(username)

    return users, failed_sudo_users, failed_sudo_events


# Gets all users that attempted to switch to a different user
def get_su_usages():
    users = []
    for username in events_by_username.keys():
        for event in events_by_username[username]:
            if event.get('event_type') == 'successful-su':
                if username not in users:
                    users.append(username)

    return users


def print_report():
    print()
    print('Here is your report:')
    print(color('-' * DEFAULT_REPORT_WIDTH, 34))

    wrap(color("1) All processes that were found in the context of the file.", 32))
    wrap(report_data['processes'])
    print()

    wrap(color("2) All usernames that were found in the context of the file.", 32))
    usernames_display = []
    for user in events_by_username.keys():
        usernames_display.append(f"{user} ({len(events_by_username[user])})")
    wrap(usernames_display)
    print()

    wrap(color("3) All successfully logins.", 32))
    wrap(report_data['successful_logins'])
    print()

    wrap(color("4) All usernames with failed login attempts.", 32))
    wrap(report_data['failed_logins'])
    print()

    wrap(color("5) All invalid usernames detected.", 32))
    wrap(report_data['invalid_usernames'])
    print()

    wrap(color("6) All usernames that used root privileges successfully.", 32))
    wrap(report_data['sudoers'])
    print()

    wrap(color("7) All usernames that attempted to use root privileges but couldn't authenticate.", 32))
    if len(report_data['failed_sudo_events']) > 0:
        wrap(color(report_data['failed_sudo_users'], ('31;1' if len(report_data['failed_sudo_events']) > 0 else 0)))
    wrap(color(f"Events count: {len(report_data['failed_sudo_events'])}",
               ('31;1' if len(report_data['failed_sudo_events']) > 0 else 0)))
    print()

    wrap(color("8) All usernames that used the su command.", 32))
    wrap(report_data['su_usages'])
    print()

    wrap(color("9) Newly created users.", 32))
    wrap(report_data['created_users'])
    print()

    wrap(color("10) Newly created groups.", 32))
    wrap(report_data['created_groups'])
    print()

    wrap(color("11) Deleted users.", 32))
    wrap(report_data['deleted_users'])
    print()

    wrap(color("12) Password changes.", 32))
    wrap(report_data['password_changes'])
    print()

    print(color('-' * DEFAULT_REPORT_WIDTH, 34))


def read_username_from_input(cmd):
    if len(cmd.split()) == 2:
        return cmd.split()[1]


def show_menu():
    print()
    wrap(color(
        "Enter option followed by username (if applicable). Example: '2 root' will print the command history for user 'root'.",
        33))
    wrap(color("1) Show all events for user", DEFAULT_MENU_COLOR))
    wrap(color("2) Show command history for user", DEFAULT_MENU_COLOR))
    wrap(color("3) Show failed login attempts for user by IP", DEFAULT_MENU_COLOR))
    wrap(color("4) Show successful logins for user by IP", DEFAULT_MENU_COLOR))
    wrap(color("5) Show max authentication attempts exceeded events", DEFAULT_MENU_COLOR))
    wrap(color("6) Show create and delete user events", DEFAULT_MENU_COLOR))
    wrap(color("7) Show password change events", DEFAULT_MENU_COLOR))
    wrap(color("8) Print report again", DEFAULT_MENU_COLOR))
    wrap(color("9) Monitor the log file in real time", DEFAULT_MENU_COLOR))
    wrap(color("q) Quit", DEFAULT_MENU_COLOR))
    print()

    cmd = input("> ").strip()
    if not cmd:
        print(color("Invalid option!", ERROR_COLOR_CODE))
        return
    option = cmd.split()[0]
    username = read_username_from_input(cmd)

    print()
    print(color('=' * DEFAULT_REPORT_WIDTH, 32))
    try:
        if option == '1':
            show_all_events(username)
        elif option == '2':
            show_command_history(username)
        elif option == '3':
            show_failed_login_attempts(username)
        elif option == '4':
            show_successful_login_attempts(username)
        elif option == '5':
            show_max_authentication_attempts_exceeded_events()
        elif option == '6':
            show_create_delete_events()
        elif option == '7':
            show_password_change_events()
        elif option == '8':
            print_report()
        elif option == '9':
            filter_keyword = input(color(
                "Do you want to add a display filter by keyword [user|command|ip address|./ for script executions|...])? Leave empty for no filter: ",
                33))
            run_monitor(filter_keyword)
        elif option == 'q' or option == 'quit':
            exit(0)
        else:
            print(color("Invalid option!", ERROR_COLOR_CODE))
    except KeyError:
        print(color("Username doesn't exist.", ERROR_COLOR_CODE))

    print(color('=' * DEFAULT_REPORT_WIDTH, 32))


def show_all_events(username):
    for event in events_by_username[username]:
        print(event)


def show_command_history(username):
    for event in events_by_username[username]:
        if event.get('event_type') == 'sudo-command':
            print(
                f"#{event.get('line_number'):<{10}} {event.get('event').get('timestamp')}   Directory: {event.get('event').get('pwd'):<{70}} {color(event.get('event').get('command'), 34)}")


def show_failed_login_attempts(username):
    failed_attempts = {}
    for event in events_by_username[username]:
        if event.get('event_type') == 'failed-login':
            event_details = event.get('event')
            timestamp = event_details.get('timestamp')
            process = event_details.get('process')
            ip = event_details.get('ip_address')
            port = event_details.get('port')
            protocol = event_details.get('protocol')
            auth_method = event_details.get('auth_method')
            ssh_signature = event_details.get('ssh_signature')
            if ip not in failed_attempts.keys():
                failed_attempts[ip] = []

            failed_attempts[ip].append(
                f"#{event.get('line_number'):<{10}} {timestamp} process: {process} port: {port}, protocol: {protocol}, method: {auth_method} {ssh_signature if ssh_signature else ''}")

    for ip in failed_attempts.keys():
        print(color(f"{ip} ({len(failed_attempts[ip])}):", 32))
        output = '\n'.join(failed_attempts[ip])
        print(output)
        print()

    if len(failed_attempts.keys()) > 0:
        print("Unique ip-s")
        wrap(list(failed_attempts.keys()))


def show_successful_login_attempts(username):
    logins = {}
    for event in events_by_username[username]:
        if event.get('event_type') == 'successful-login':
            event_details = event.get('event')
            timestamp = event_details.get('timestamp')
            process = event_details.get('process')
            ip = event_details.get('ip_address')
            port = event_details.get('port')
            protocol = event_details.get('protocol')
            auth_method = event_details.get('auth_method')
            ssh_signature = event_details.get('ssh_signature')
            if ip not in logins.keys():
                logins[ip] = []

            logins[ip].append(
                f"#{event.get('line_number'):<{10}} {timestamp} process: {process} port: {port}, protocol: {protocol}, method: {auth_method} {ssh_signature if ssh_signature else ''}")

    for ip in logins.keys():
        print(color(f"{ip} ({len(logins[ip])}):", 32))
        output = '\n'.join(logins[ip])
        print(output)
        print()

    if len(logins.keys()) > 0:
        wrap("Unique ip-s")
        wrap(list(logins.keys()))


def show_max_authentication_attempts_exceeded_events():
    for event in saved_events:
        if event.get('event_type') == 'max-authentication-attempts-exceeded':
            details = event.get('event_details')
            print(
                f"#{event.get('line_number'):<{10}} {details.get('timestamp')} username: {details.get('username')} ip: {details.get('ip_address')} port: {details.get('port')} protocol: {details.get('protocol')}")


def show_create_delete_events():
    for event in saved_events:
        if event.get('event_type') == 'user-created' or event.get('event_type') == 'user-deleted':
            details = event.get('event_details')
            print(
                f"#{event.get('line_number'):<{10}} {details.get('timestamp')} process: {details.get('process')} username: {details.get('username')} user_id: {details.get('user_id')}")


def show_password_change_events():
    for event in saved_events:
        if event.get('event_type') == 'password-change':
            details = event.get('event_details')
            print(
                f"#{event.get('line_number'):<{10}} {details.get('timestamp')} process: {details.get('process')} service: {details.get('service')} username: {details.get('username')}")
        if event.get('event_type') == 'chpasswd-non-existing-user':
            details = event.get('event_details')
            print(
                f"#{event.get('line_number'):<{10}} {details.get('timestamp')} process: {details.get('process')} service: {details.get('service')} username: {details.get('username')} does not exist in /etc/passwd")


# Monitor log thread handler
def monitor_log(log_path, filter_keyword, process_line_func):
    global stop_monitoring
    stop_monitoring = False

    try:
        with open(log_path, 'r', encoding='utf-8') as log_file:
            log_file.seek(0, 2)  # Go to the end of the file

            while not stop_monitoring:
                line = log_file.readline()
                if not line:
                    time.sleep(0.1)  # Wait a bit before checking again
                    continue

                line = line.strip()
                process_line_func(line, filter_keyword)  # Process the new line
    except FileNotFoundError:
        print(f"Error: File not found: {log_path}")
    except Exception as e:
        print(f"Unhandled error in monitor_log: {e}")


# Process new log entry in live monitoring mode
def process_line(line, filter_keyword):
    if len(line) == 0:
        return

    if len(filter_keyword) != 0 and line.find(filter_keyword) == -1:
        return

    data = extract_data(line)
    if not data:
        print(color("UNRECOGNIZED PATTERN -> ", 33), line)
    else:
        details = data.get('event_details')
        if data.get('event_type') == 'sudo-command':
            info = f"'{details.get('username')}' executed command as: {details.get('sudo_user')} \t\t Directory: {details.get('pwd')}    Command: {details.get('command')}"
            print(color('ALERT! ->', 31), info)
        else:
            print(color(data.get('event_type').replace('-', ' ').upper(), 32),
                  f"[{details.get('username')}]" if details.get('username') and len(
                      details.get('username')) > 0 else '', " -> ", line)


# Start real time monitoring for new log entries
def run_monitor(filter_keyword):
    global stop_monitoring

    log_thread = threading.Thread(target=monitor_log,
                                  args=(auth_log_path, filter_keyword, process_line))
    log_thread.daemon = True
    log_thread.start()

    try:
        while True:
            command = input("Enter 'q' to stop monitoring:\n\n")
            if command.strip().lower() == 'q':
                stop_monitoring = True
                break
            time.sleep(1)
    except KeyboardInterrupt:
        stop_monitoring = True  # Handle Ctrl+C gracefully
    finally:
        print("Stopping log monitor...")


# Main application loop
def run_analyzer():
    global auth_log_path

    print_banner()
    auth_log_path = read_authlog_path()
    parse_log_file()
    analyze_log_file()
    print_report()
    input("Press ENTER to show menu.")
    try:
        while True:
            show_menu()
    except Exception as e:
        print(e)
        exit(-1)


run_analyzer()  # Starts the app
