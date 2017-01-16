# -*- coding: utf-8 -*-
"""Passdb classes to decode user entries from passdb."""

from .transcode import Password, String, Struct, Uint16, Uint32


class PassDBV0(Struct):
    """Version 0 of the passdb struct.

    Source from passdb.c
    ```
    /* SAMU_BUFFER_FORMAT_V0       "ddddddBBBBBBBBBBBBddBBwdwdBwwd" */

    /* unpack the buffer into variables */
    len = tdb_unpack (buf, buflen, SAMU_BUFFER_FORMAT_V0,
        &logon_time,						/* d */
        &logoff_time,						/* d */
        &kickoff_time,						/* d */
        &pass_last_set_time,					/* d */
        &pass_can_change_time,					/* d */
        &pass_must_change_time,					/* d */
        &username_len, &username,				/* B */
        &domain_len, &domain,					/* B */
        &nt_username_len, &nt_username,				/* B */
        &fullname_len, &fullname,				/* B */
        &homedir_len, &homedir,					/* B */
        &dir_drive_len, &dir_drive,				/* B */
        &logon_script_len, &logon_script,			/* B */
        &profile_path_len, &profile_path,			/* B */
        &acct_desc_len, &acct_desc,				/* B */
        &workstations_len, &workstations,			/* B */
        &unknown_str_len, &unknown_str,				/* B */
        &munged_dial_len, &munged_dial,				/* B */
        &user_rid,						/* d */
        &group_rid,						/* d */
        &lm_pw_len, &lm_pw_ptr,					/* B */
        &nt_pw_len, &nt_pw_ptr,					/* B */
        &acct_ctrl,						/* w */
        &remove_me, /* remove on the next TDB_FORMAT upgarde */	/* d */
        &logon_divs,						/* w */
        &hours_len,						/* d */
        &hourslen, &hours,					/* B */
        &bad_Password_count,					/* w */
        &logon_count,						/* w */
        &unknown_6);						/* d */
    ```
    """

    attributes_map = [
        ('logon_time', Uint32),
        ('logoff_time', Uint32),
        ('kickoff_time', Uint32),
        ('pass_last_set_time', Uint32),
        ('pass_can_change_time', Uint32),
        ('pass_must_change_time', Uint32),
        ('username', String),
        ('domain', String),
        ('nt_username', String),
        ('fullname', String),
        ('homedir', String),
        ('dir_drive', String),
        ('logon_script', String),
        ('profile_path', String),
        ('acct_desc', String),
        ('workstations', String),
        ('unknown_str', String),
        ('munged_dial', String),
        ('user_rid', Uint32),
        ('group_rid', Uint32),
        ('lm_pw_ptr', Password),
        ('nt_pw_ptr', Password),
        ('acct_ctrl', Uint16),
        ('remove_me', Uint32),
        ('logon_divs', Uint16),
        ('hours_len', Uint32),
        ('hours', String),
        ('bad_Password_count', Uint16),
        ('logon_count', Uint16),
        ('unknown_6', Uint32),
    ]


class PassDBV1(Struct):
    """Version 1 of the passdb struct.

    Source from passdb.c
    ```
    /* SAMU_BUFFER_FORMAT_V1       "dddddddBBBBBBBBBBBBddBBwdwdBwwd" */

    /* unpack the buffer into variables */
    len = tdb_unpack (buf, buflen, SAMU_BUFFER_FORMAT_V1,
        &logon_time,						/* d */
        &logoff_time,						/* d */
        &kickoff_time,						/* d */
        /* Change from V0 is addition of bad_Password_time field. */
        &bad_Password_time,					/* d */
        &pass_last_set_time,					/* d */
        &pass_can_change_time,					/* d */
        &pass_must_change_time,					/* d */
        &username_len, &username,				/* B */
        &domain_len, &domain,					/* B */
        &nt_username_len, &nt_username,				/* B */
        &fullname_len, &fullname,				/* B */
        &homedir_len, &homedir,					/* B */
        &dir_drive_len, &dir_drive,				/* B */
        &logon_script_len, &logon_script,			/* B */
        &profile_path_len, &profile_path,			/* B */
        &acct_desc_len, &acct_desc,				/* B */
        &workstations_len, &workstations,			/* B */
        &unknown_str_len, &unknown_str,				/* B */
        &munged_dial_len, &munged_dial,				/* B */
        &user_rid,						/* d */
        &group_rid,						/* d */
        &lm_pw_len, &lm_pw_ptr,					/* B */
        &nt_pw_len, &nt_pw_ptr,					/* B */
        &acct_ctrl,						/* w */
        &remove_me,						/* d */
        &logon_divs,						/* w */
        &hours_len,						/* d */
        &hourslen, &hours,					/* B */
        &bad_Password_count,					/* w */
        &logon_count,						/* w */
        &unknown_6);						/* d */
    ```
    """

    attributes_map = [
        ('logon_time', Uint32),
        ('logoff_time', Uint32),
        ('kickoff_time', Uint32),
        ('bad_Password_time', Uint32),
        ('pass_last_set_time', Uint32),
        ('pass_can_change_time', Uint32),
        ('pass_must_change_time', Uint32),
        ('username', String),
        ('domain', String),
        ('nt_username', String),
        ('fullname', String),
        ('homedir', String),
        ('dir_drive', String),
        ('logon_script', String),
        ('profile_path', String),
        ('acct_desc', String),
        ('workstations', String),
        ('unknown_str', String),
        ('munged_dial', String),
        ('user_rid', Uint32),
        ('group_rid', Uint32),
        ('lm_pw_ptr', Password),
        ('nt_pw_ptr', Password),
        ('acct_ctrl', Uint16),
        ('remove_me', Uint32),
        ('logon_divs', Uint16),
        ('hours_len', Uint32),
        ('hours', String),
        ('bad_Password_count', Uint16),
        ('logon_count', Uint16),
        ('unknown_6', Uint32),
    ]


class PassDBV2(Struct):
    """Version 1 of the passdb struct.

    Source from passdb.c
    ```
    /* SAMU_BUFFER_FORMAT_V2       "dddddddBBBBBBBBBBBBddBBBwwdBwwd" */

    /* unpack the buffer into variables */
    len = tdb_unpack (buf, buflen, SAMU_BUFFER_FORMAT_V2,
        &logon_time,						/* d */
        &logoff_time,						/* d */
        &kickoff_time,						/* d */
        &bad_Password_time,					/* d */
        &pass_last_set_time,					/* d */
        &pass_can_change_time,					/* d */
        &pass_must_change_time,					/* d */
        &username_len, &username,				/* B */
        &domain_len, &domain,					/* B */
        &nt_username_len, &nt_username,				/* B */
        &fullname_len, &fullname,				/* B */
        &homedir_len, &homedir,					/* B */
        &dir_drive_len, &dir_drive,				/* B */
        &logon_script_len, &logon_script,			/* B */
        &profile_path_len, &profile_path,			/* B */
        &acct_desc_len, &acct_desc,				/* B */
        &workstations_len, &workstations,			/* B */
        &unknown_str_len, &unknown_str,				/* B */
        &munged_dial_len, &munged_dial,				/* B */
        &user_rid,						/* d */
        &group_rid,						/* d */
        &lm_pw_len, &lm_pw_ptr,					/* B */
        &nt_pw_len, &nt_pw_ptr,					/* B */
        /* Change from V1 is addition of Password history field. */
        &nt_pw_hist_len, &nt_pw_hist_ptr,			/* B */
        &acct_ctrl,						/* w */
        /* Also "remove_me" field was removed. */
        &logon_divs,						/* w */
        &hours_len,						/* d */
        &hourslen, &hours,					/* B */
        &bad_Password_count,					/* w */
        &logon_count,						/* w */
        &unknown_6);						/* d */
    ```
    """

    attributes_map = [
        ('logon_time', Uint32),
        ('logoff_time', Uint32),
        ('kickoff_time', Uint32),
        ('bad_Password_time', Uint32),
        ('pass_last_set_time', Uint32),
        ('pass_can_change_time', Uint32),
        ('pass_must_change_time', Uint32),
        ('username', String),
        ('domain', String),
        ('nt_username', String),
        ('fullname', String),
        ('homedir', String),
        ('dir_drive', String),
        ('logon_script', String),
        ('profile_path', String),
        ('acct_desc', String),
        ('workstations', String),
        ('unknown_str', String),
        ('munged_dial', String),
        ('user_rid', Uint32),
        ('group_rid', Uint32),
        ('lm_pw_ptr', Password),
        ('nt_pw_ptr', Password),
        ('nt_history', String),
        ('acct_ctrl', Uint16),
        ('logon_divs', Uint16),
        ('hours_len', Uint32),
        ('hours', String),
        ('bad_Password_count', Uint16),
        ('logon_count', Uint16),
        ('unknown_6', Uint32),
    ]


class PassDBV3(Struct):
    """Version 1 of the passdb struct.

    Source from passdb.c
    ```
    /* SAMU_BUFFER_FORMAT_V3       "dddddddBBBBBBBBBBBBddBBBdwdBwwd" */

    /* unpack the buffer into variables */
    len = tdb_unpack (buf, buflen, SAMU_BUFFER_FORMAT_V3,
        &logon_time,						/* d */
        &logoff_time,						/* d */
        &kickoff_time,						/* d */
        &bad_Password_time,					/* d */
        &pass_last_set_time,					/* d */
        &pass_can_change_time,					/* d */
        &pass_must_change_time,					/* d */
        &username_len, &username,				/* B */
        &domain_len, &domain,					/* B */
        &nt_username_len, &nt_username,				/* B */
        &fullname_len, &fullname,				/* B */
        &homedir_len, &homedir,					/* B */
        &dir_drive_len, &dir_drive,				/* B */
        &logon_script_len, &logon_script,			/* B */
        &profile_path_len, &profile_path,			/* B */
        &acct_desc_len, &acct_desc,				/* B */
        &workstations_len, &workstations,			/* B */
        &comment_len, &comment,					/* B */
        &munged_dial_len, &munged_dial,				/* B */
        &user_rid,						/* d */
        &group_rid,						/* d */
        &lm_pw_len, &lm_pw_ptr,					/* B */
        &nt_pw_len, &nt_pw_ptr,					/* B */
        /* Change from V1 is addition of Password history field. */
        &nt_pw_hist_len, &nt_pw_hist_ptr,			/* B */
        /* Change from V2 is the Uint32_t acb_mask */
        &acct_ctrl,						/* d */
        /* Also "remove_me" field was removed. */
        &logon_divs,						/* w */
        &hours_len,						/* d */
        &hourslen, &hours,					/* B */
        &bad_Password_count,					/* w */
        &logon_count,						/* w */
        &unknown_6);						/* d */
    ```
    """

    attributes_map = [
        ('logon_time', Uint32),
        ('logoff_time', Uint32),
        ('kickoff_time', Uint32),
        ('bad_Password_time', Uint32),
        ('pass_last_set_time', Uint32),
        ('pass_can_change_time', Uint32),
        ('pass_must_change_time', Uint32),
        ('username', String),
        ('domain', String),
        ('nt_username', String),
        ('fullname', String),
        ('homedir', String),
        ('dir_drive', String),
        ('logon_script', String),
        ('profile_path', String),
        ('acct_desc', String),
        ('workstations', String),
        ('comment', String),
        ('munged_dial', String),
        ('user_rid', Uint32),
        ('group_rid', Uint32),
        ('lm_pw_ptr', Password),
        ('nt_pw_ptr', Password),
        ('nt_history', String),
        ('acct_ctrl', Uint32),
        ('logon_divs', Uint16),
        ('hours_len', Uint32),
        ('hours', String),
        ('bad_Password_count', Uint16),
        ('logon_count', Uint16),
        ('unknown_6', Uint32),
    ]
