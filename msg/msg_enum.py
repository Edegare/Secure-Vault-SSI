from enum import Enum


class MESSAGE_TYPE(Enum):
    ERROR = 1
    ADD = 2
    LIST = 3
    SHARE = 4
    DELETE = 5
    REPLACE = 6
    DETAILS = 7
    REVOKE = 8
    READ = 9
    GROUP_CREATE = 10
    GROUP_DELETE = 11
    GROUP_DETAILS = 12
    GROUP_ADD_USER = 13
    GROUP_DELETE_USER = 14
    GROUP_LIST = 15
    GROUP_ADD = 16
    EXIT = 17
    SUCCESS = 18
