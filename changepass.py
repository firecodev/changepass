#!/usr/bin/env python

import sys
import threading
import logging
from time import sleep
import paramiko

auth_profile = {
    "switch": {
        "username": "admin",
        "password": "p@ssw0rd"
    },
    "router": {
        "username": "admin",
        "password": "pa55wo2d"
    }
}

command_list = {
    "icx7250_switch": (
        "configure terminal",
        "username admin password newp@ssw0rd",
        "enable super-user-password newen@blepwd",
        "exit",
        "write memory"
    ),
    "icx7250_router": (
        "enable",
        "en@blepwd",
        "configure terminal",
        "username admin password",
        "newpa55wo2d",
        "enable super-user-password",
        "newen@blepwd",
        "exit",
        "write memory"
    ),
    "c3750_router": (
        "enable",
        "en@blepwd",
        "configure terminal",
        "username admin secret newpa55wo2d",
        "enable secret newen@blepwd",
        "exit",
        "write memory"
    ),
    "icx7150_wifirouter": (
        "enable",
        "en@blepwd",
        "configure terminal",
        "username admin password newpa55wo2d",
        "enable super-user-password newen@blepwd",
        "exit",
        "write memory"
    ),
    "test_switch": (
    ),
    "test_router": (
    )
}

# [(ip, auth_profile, command_list)]
device_list = [
    ("192.168.1.1", "switch", "icx7250_switch"),
    ("192.168.1.2", "switch", "icx7250_switch"),
    ("192.168.1.3", "switch", "icx7250_switch"),
    ("192.168.1.4", "router", "icx7150_wifirouter"),
    ("192.168.1.5", "router", "icx7150_wifirouter"),
    ("192.168.1.6", "router", "icx7150_wifirouter"),
    ("192.168.1.7", "router", "c3750_router"),
    ("192.168.1.8", "router", "c3750_router"),
    ("192.168.1.9", "router", "c3750_router"),
    ("192.168.1.10", "router", "icx7250_router"),
    ("192.168.1.11", "router", "icx7250_router"),
    ("192.168.1.12", "router", "icx7250_router")
]


def get_ssh(ip: str, username: str, password: str, port: int):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=ip, port=port, username=username,
                password=password, look_for_keys=False, allow_agent=False)
    return ssh


def exec_command(ssh: paramiko.SSHClient, commands: tuple):
    output = bytes("", "ascii")
    shell = ssh.invoke_shell()
    try:
        for command in commands:
            shell.send(command + "\n")
            if command in ("write memory"):
                sleep(7)
            else:
                sleep(1)
            response = shell.recv(65536)
            output += response
    except Exception as e:
        raise RuntimeError(
            "Error occured after receiving these output:\n" + output.decode()) from e


def close_ssh(ssh: paramiko.SSHClient):
    ssh.close()


def thread_job(device, error_msg_bucket: list):
    device_ip = device[0]
    device_auth_profile = device[1]
    device_command_list = command_list[device[2]]

    device_username = auth_profile[device_auth_profile]["username"]
    device_password = auth_profile[device_auth_profile]["password"]

    try:
        ssh = get_ssh(device_ip, device_username, device_password, 22)
        logging.info("Connected to " + device_ip + " .")
        exec_command(ssh, device_command_list)
        close_ssh(ssh)
    except Exception as e:
        logging.error("Error occured when doing job of " + device_ip + " !")
        error_msg_bucket.append(device_ip + ":\n" + str(e))


def main():
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)
    logging.info("Program started.")

    thread_pool = []
    error_msg_bucket = []

    for device in device_list:
        new_thread = threading.Thread(
            target=thread_job, args=(device, error_msg_bucket))
        new_thread.daemon = True
        new_thread.start()
        thread_pool.append(new_thread)

    for thread in thread_pool:
        thread.join()

    logging.info("All jobs are finished.")

    if error_msg_bucket:
        for error_msg in error_msg_bucket:
            logging.error(error_msg)

    return 0


if __name__ == "__main__":
    sys.exit(main())
