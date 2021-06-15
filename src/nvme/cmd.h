// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 *
 * Authors: Keith Busch <keith.busch@wdc.com>
 *          Chaitanya Kulkarni <chaitanya.kulkarni@wdc.com>
 */

#ifndef _LIBNVME_CMD_H
#define _LIBNVME_CMD_H

/**
 * enum nvme_admin_opcode - Known NVMe admin opcodes
 * @nvme_admin_delete_sq:
 * @nvme_admin_create_sq:
 * @nvme_admin_get_log_page:
 * @nvme_admin_delete_cq:
 * @nvme_admin_create_cq:
 * @nvme_admin_identify:
 * @nvme_admin_abort_cmd:
 * @nvme_admin_set_features:
 * @nvme_admin_get_features:
 * @nvme_admin_async_event:
 * @nvme_admin_ns_mgmt:
 * @nvme_admin_fw_commit:
 * @nvme_admin_fw_download:
 * @nvme_admin_dev_self_test:
 * @nvme_admin_ns_attach:
 * @nvme_admin_keep_alive:
 * @nvme_admin_directive_send:
 * @nvme_admin_directive_recv:
 * @nvme_admin_virtual_mgmt:
 * @nvme_admin_nvme_mi_send:
 * @nvme_admin_nvme_mi_recv:
 * @nvme_admin_dbbuf:
 * @nvme_admin_fabrics:
 * @nvme_admin_format_nvm:
 * @nvme_admin_security_send:
 * @nvme_admin_security_recv:
 * @nvme_admin_sanitize_nvm:
 * @nvme_admin_get_lba_status:
 */
enum nvme_admin_opcode {
	nvme_admin_delete_sq		= 0x00,
	nvme_admin_create_sq		= 0x01,
	nvme_admin_get_log_page		= 0x02,
	nvme_admin_delete_cq		= 0x04,
	nvme_admin_create_cq		= 0x05,
	nvme_admin_identify		= 0x06,
	nvme_admin_abort_cmd		= 0x08,
	nvme_admin_set_features		= 0x09,
	nvme_admin_get_features		= 0x0a,
	nvme_admin_async_event		= 0x0c,
	nvme_admin_ns_mgmt		= 0x0d,
	nvme_admin_fw_commit		= 0x10,
	nvme_admin_fw_activate		= nvme_admin_fw_commit,
	nvme_admin_fw_download		= 0x11,
	nvme_admin_dev_self_test	= 0x14,
	nvme_admin_ns_attach		= 0x15,
	nvme_admin_keep_alive		= 0x18,
	nvme_admin_directive_send	= 0x19,
	nvme_admin_directive_recv	= 0x1a,
	nvme_admin_virtual_mgmt		= 0x1c,
	nvme_admin_nvme_mi_send		= 0x1d,
	nvme_admin_nvme_mi_recv		= 0x1e,
	nvme_admin_dbbuf		= 0x7c,
	nvme_admin_fabrics		= 0x7f,
	nvme_admin_format_nvm		= 0x80,
	nvme_admin_security_send	= 0x81,
	nvme_admin_security_recv	= 0x82,
	nvme_admin_sanitize_nvm		= 0x84,
	nvme_admin_get_lba_status	= 0x86,
};

/**
 * enum nvme_identify_cns -
 * @NVME_IDENTIFY_CNS_NS:
 * @NVME_IDENTIFY_CNS_CTRL:
 * @NVME_IDENTIFY_CNS_NS_ACTIVE_LIST:
 * @NVME_IDENTIFY_CNS_NS_DESC_LIST:
 * @NVME_IDENTIFY_CNS_NVMSET_LIST:
 * @NVME_IDENTIFY_CNS_CSI_NS:
 * @NVME_IDENTIFY_CNS_CSI_CTRL:
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST:
 * @NVME_IDENTIFY_CNS_ALLOCATED_NS:
 * @NVME_IDENTIFY_CNS_NS_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP:
 * @NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST:
 * @NVME_IDENTIFY_CNS_NS_GRANULARITY:
 * @NVME_IDENTIFY_CNS_UUID_LIST:
 * @NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS:
 */
enum nvme_identify_cns {
	NVME_IDENTIFY_CNS_NS					= 0x00,
	NVME_IDENTIFY_CNS_CTRL					= 0x01,
	NVME_IDENTIFY_CNS_NS_ACTIVE_LIST			= 0x02,
	NVME_IDENTIFY_CNS_NS_DESC_LIST				= 0x03,
	NVME_IDENTIFY_CNS_NVMSET_LIST				= 0x04,
	NVME_IDENTIFY_CNS_CSI_NS				= 0x05, /* XXX: Placeholder until assigned */
	NVME_IDENTIFY_CNS_CSI_CTRL				= 0x06, /* XXX: Placeholder until assigned */
	NVME_IDENTIFY_CNS_ALLOCATED_NS_LIST			= 0x10,
	NVME_IDENTIFY_CNS_ALLOCATED_NS				= 0x11,
	NVME_IDENTIFY_CNS_NS_CTRL_LIST				= 0x12,
	NVME_IDENTIFY_CNS_CTRL_LIST				= 0x13,
	NVME_IDENTIFY_CNS_PRIMARY_CTRL_CAP			= 0x14,
	NVME_IDENTIFY_CNS_SECONDARY_CTRL_LIST			= 0x15,
	NVME_IDENTIFY_CNS_NS_GRANULARITY			= 0x16,
	NVME_IDENTIFY_CNS_UUID_LIST				= 0x17,
	NVME_IDENTIFY_CNS_CSI_ALLOCATED_NS			= 0x18, /* XXX: Placeholder until assigned */
};

/**
 * enum nvme_cmd_get_log_lid -
 * @NVME_LOG_LID_ERROR:
 * @NVME_LOG_LID_SMART:
 * @NVME_LOG_LID_FW_SLOT:
 * @NVME_LOG_LID_CHANGED_NS:
 * @NVME_LOG_LID_CMD_EFFECTS:
 * @NVME_LOG_LID_DEVICE_SELF_TEST:
 * @NVME_LOG_LID_TELEMETRY_HOST:
 * @NVME_LOG_LID_TELEMETRY_CTRL:
 * @NVME_LOG_LID_ENDURANCE_GROUP:
 * @NVME_LOG_LID_PREDICTABLE_LAT_NVMSET:
 * @NVME_LOG_LID_PREDICTABLE_LAT_AGG:
 * @NVME_LOG_LID_ANA:
 * @NVME_LOG_LID_PERSISTENT_EVENT:
 * @NVME_LOG_LID_LBA_STATUS:
 * @NVME_LOG_LID_ENDURANCE_GRP_EVT:
 * @NVME_LOG_LID_DISCOVER:
 * @NVME_LOG_LID_RESERVATION:
 * @NVME_LOG_LID_SANITIZE:
 * @NVME_LOG_LID_ZNS_CHANGED_ZONES:
 */
enum nvme_cmd_get_log_lid {
	NVME_LOG_LID_ERROR					= 0x01,
	NVME_LOG_LID_SMART					= 0x02,
	NVME_LOG_LID_FW_SLOT					= 0x03,
	NVME_LOG_LID_CHANGED_NS					= 0x04,
	NVME_LOG_LID_CMD_EFFECTS				= 0x05,
	NVME_LOG_LID_DEVICE_SELF_TEST				= 0x06,
	NVME_LOG_LID_TELEMETRY_HOST				= 0x07,
	NVME_LOG_LID_TELEMETRY_CTRL				= 0x08,
	NVME_LOG_LID_ENDURANCE_GROUP				= 0x09,
	NVME_LOG_LID_PREDICTABLE_LAT_NVMSET			= 0x0a,
	NVME_LOG_LID_PREDICTABLE_LAT_AGG			= 0x0b,
	NVME_LOG_LID_ANA					= 0x0c,
	NVME_LOG_LID_PERSISTENT_EVENT				= 0x0d,
	NVME_LOG_LID_LBA_STATUS					= 0x0e,
	NVME_LOG_LID_ENDURANCE_GRP_EVT				= 0x0f,
	NVME_LOG_LID_DISCOVER					= 0x70,
	NVME_LOG_LID_RESERVATION				= 0x80,
	NVME_LOG_LID_SANITIZE					= 0x81,
	NVME_LOG_LID_ZNS_CHANGED_ZONES				= 0xbf,
};

/**
 * enum nvme_features_id -
 * @NVME_FEAT_FID_ARBITRATION:
 * @NVME_FEAT_FID_POWER_MGMT:
 * @NVME_FEAT_FID_LBA_RANGE:
 * @NVME_FEAT_FID_TEMP_THRESH:
 * @NVME_FEAT_FID_ERR_RECOVERY:
 * @NVME_FEAT_FID_VOLATILE_WC:
 * @NVME_FEAT_FID_NUM_QUEUES:
 * @NVME_FEAT_FID_IRQ_COALESCE:
 * @NVME_FEAT_FID_IRQ_CONFIG:
 * @NVME_FEAT_FID_WRITE_ATOMIC:
 * @NVME_FEAT_FID_ASYNC_EVENT:
 * @NVME_FEAT_FID_AUTO_PST:
 * @NVME_FEAT_FID_HOST_MEM_BUF:
 * @NVME_FEAT_FID_TIMESTAMP:
 * @NVME_FEAT_FID_KATO:
 * @NVME_FEAT_FID_HCTM:
 * @NVME_FEAT_FID_NOPSC:
 * @NVME_FEAT_FID_RRL:
 * @NVME_FEAT_FID_PLM_CONFIG:
 * @NVME_FEAT_FID_PLM_WINDOW:
 * @NVME_FEAT_FID_LBA_STS_INTERVAL:
 * @NVME_FEAT_FID_HOST_BEHAVIOR:
 * @NVME_FEAT_FID_SANITIZE:
 * @NVME_FEAT_FID_ENDURANCE_EVT_CFG:
 * @NVME_FEAT_FID_IOCS_PROFILE:
 * @NVME_FEAT_FID_SW_PROGRESS:
 * @NVME_FEAT_FID_HOST_ID:
 * @NVME_FEAT_FID_RESV_MASK:
 * @NVME_FEAT_FID_RESV_PERSIST:
 * @NVME_FEAT_FID_WRITE_PROTECT:
 */
enum nvme_features_id {
	NVME_FEAT_FID_ARBITRATION				= 0x01,
	NVME_FEAT_FID_POWER_MGMT				= 0x02,
	NVME_FEAT_FID_LBA_RANGE					= 0x03,
	NVME_FEAT_FID_TEMP_THRESH				= 0x04,
	NVME_FEAT_FID_ERR_RECOVERY				= 0x05,
	NVME_FEAT_FID_VOLATILE_WC				= 0x06,
	NVME_FEAT_FID_NUM_QUEUES				= 0x07,
	NVME_FEAT_FID_IRQ_COALESCE				= 0x08,
	NVME_FEAT_FID_IRQ_CONFIG				= 0x09,
	NVME_FEAT_FID_WRITE_ATOMIC				= 0x0a,
	NVME_FEAT_FID_ASYNC_EVENT				= 0x0b,
	NVME_FEAT_FID_AUTO_PST					= 0x0c,
	NVME_FEAT_FID_HOST_MEM_BUF				= 0x0d,
	NVME_FEAT_FID_TIMESTAMP					= 0x0e,
	NVME_FEAT_FID_KATO					= 0x0f,
	NVME_FEAT_FID_HCTM					= 0x10,
	NVME_FEAT_FID_NOPSC					= 0x11,
	NVME_FEAT_FID_RRL					= 0x12,
	NVME_FEAT_FID_PLM_CONFIG				= 0x13,
	NVME_FEAT_FID_PLM_WINDOW				= 0x14,
	NVME_FEAT_FID_LBA_STS_INTERVAL				= 0x15,
	NVME_FEAT_FID_HOST_BEHAVIOR				= 0x16,
	NVME_FEAT_FID_SANITIZE					= 0x17,
	NVME_FEAT_FID_ENDURANCE_EVT_CFG				= 0x18,
	NVME_FEAT_FID_IOCS_PROFILE				= 0x19, /* XXX: Placeholder until assigned */
	NVME_FEAT_FID_SW_PROGRESS				= 0x80,
	NVME_FEAT_FID_HOST_ID					= 0x81,
	NVME_FEAT_FID_RESV_MASK					= 0x82,
	NVME_FEAT_FID_RESV_PERSIST				= 0x83,
	NVME_FEAT_FID_WRITE_PROTECT				= 0x84,
};

/**
 * enum nvme_get_features_sel -
 * @NVME_GET_FEATURES_SEL_CURRENT:
 * @NVME_GET_FEATURES_SEL_DEFAULT:
 * @NVME_GET_FEATURES_SEL_SAVED:
 */
enum nvme_get_features_sel {
	NVME_GET_FEATURES_SEL_CURRENT				= 0,
	NVME_GET_FEATURES_SEL_DEFAULT				= 1,
	NVME_GET_FEATURES_SEL_SAVED				= 2,
	NVME_GET_FEATURES_SEL_SUPPORTED				= 3,
};

/**
 * enum nvme_cmd_format_mset -
 * @NVME_FORMAT_MSET_SEPARATE:
 * @NVME_FORMAT_MSET_EXTENEDED:
 */
enum nvme_cmd_format_mset {
	NVME_FORMAT_MSET_SEPARATE				= 0,
	NVME_FORMAT_MSET_EXTENEDED				= 1,
};

/**
 * enum nvme_cmd_format_pi -
 * @NVME_FORMAT_PI_DISABLE:
 * @NVME_FORMAT_PI_TYPE1:
 * @NVME_FORMAT_PI_TYPE2:
 * @NVME_FORMAT_PI_TYPE3:
 */
enum nvme_cmd_format_pi {
	NVME_FORMAT_PI_DISABLE					= 0,
	NVME_FORMAT_PI_TYPE1					= 1,
	NVME_FORMAT_PI_TYPE2					= 2,
	NVME_FORMAT_PI_TYPE3					= 3,
};

/**
 * @enum nvme_cmd_format_pil -
 * @NVME_FORMAT_PIL_LAST:
 * @NVME_FORMAT_PIL_FIRST:
 */
enum nvme_cmd_format_pil {
	NVME_FORMAT_PIL_LAST					= 0,
	NVME_FORMAT_PIL_FIRST					= 1,
};

/**
 * enum nvme_cmd_format_ses -
 * @NVME_FORMAT_SES_NONE:
 * @NVME_FORMAT_SES_USER_DATA_ERASE:
 * @NVME_FORMAT_SES_CRYPTO_ERASE:
 */
enum nvme_cmd_format_ses {
	NVME_FORMAT_SES_NONE					= 0,
	NVME_FORMAT_SES_USER_DATA_ERASE				= 1,
	NVME_FORMAT_SES_CRYPTO_ERASE				= 2,
};

/**
 * enum nvme_ns_mgmt_sel -
 * @NVME_NAMESPACE_MGMT_SEL_CREATE:
 * @NVME_NAMESPACE_MGMT_SEL_DELETE:
 */
enum nvme_ns_mgmt_sel {
	NVME_NS_MGMT_SEL_CREATE					= 0,
	NVME_NS_MGMT_SEL_DELETE					= 1,
};

/**
 * enum nvme_ns_attach_sel -
 * NVME_NS_ATTACH_SEL_CTRL_ATTACH:
 * NVME_NP_ATTACH_SEL_CTRL_DEATTACH:
 */
enum nvme_ns_attach_sel {
	NVME_NS_ATTACH_SEL_CTRL_ATTACH				= 0,
	NVME_NS_ATTACH_SEL_CTRL_DEATTACH			= 1,
};

/**
 * enum nvme_fw_commit_ca -
 * @NVME_FW_COMMIT_CA_REPLACE:
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE:
 * @NVME_FW_COMMIT_CA_SET_ACTIVE:
 * @NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE:
 * @NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION:
 * @NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION:
 */
enum nvme_fw_commit_ca {
	NVME_FW_COMMIT_CA_REPLACE				= 0,
	NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE			= 1,
	NVME_FW_COMMIT_CA_SET_ACTIVE				= 2,
	NVME_FW_COMMIT_CA_REPLACE_AND_ACTIVATE_IMMEDIATE	= 3,
	NVME_FW_COMMIT_CA_REPLACE_BOOT_PARTITION		= 6,
	NVME_FW_COMMIT_CA_ACTIVATE_BOOT_PARTITION		= 7,
};

/**
 * enum nvme_directive_dtype -
 * @NVME_DIRECTIVE_DTYPE_IDENTIFY:
 * @NVME_DIRECTIVE_DTYPE_STREAMS:
 */
enum nvme_directive_dtype {
	NVME_DIRECTIVE_DTYPE_IDENTIFY				= 0,
	NVME_DIRECTIVE_DTYPE_STREAMS				= 1,
};

/**
 * enum nvme_directive_receive_doper -
 * @NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS:
 * @NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE:
 */
enum nvme_directive_receive_doper {
	NVME_DIRECTIVE_RECEIVE_IDENTIFY_DOPER_PARAM		= 0x01,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_PARAM		= 0x01,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_STATUS		= 0x02,
	NVME_DIRECTIVE_RECEIVE_STREAMS_DOPER_RESOURCE		= 0x03,
};

/**
 * enum nvme_directive_send_doper -
 * @NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR:
 * @NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER:
 * @NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE:
 */
enum nvme_directive_send_doper {
	NVME_DIRECTIVE_SEND_IDENTIFY_DOPER_ENDIR		= 0x01,
	NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_IDENTIFIER	= 0x01,
	NVME_DIRECTIVE_SEND_STREAMS_DOPER_RELEASE_RESOURCE	= 0x02,
};

/**
 * enum -
 */
enum nvme_directive_send_identify_endir {
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_DISABLE		= 0,
	NVME_DIRECTIVE_SEND_IDENTIFY_ENDIR_ENABLE		= 1,
};

/**
 * enum nvme_sanitize_sanact -
 * @NVME_SANITIZE_SANACT_EXIT_FAILURE:
 * @NVME_SANITIZE_SANACT_START_BLOCK_ERASE:
 * @NVME_SANITIZE_SANACT_START_OVERWRITE:
 * @NVME_SANITIZE_SANACT_START_CRYPTO_ERASE:
 */
enum nvme_sanitize_sanact {
	NVME_SANITIZE_SANACT_EXIT_FAILURE			= 1,
	NVME_SANITIZE_SANACT_START_BLOCK_ERASE			= 2,
	NVME_SANITIZE_SANACT_START_OVERWRITE			= 3,
	NVME_SANITIZE_SANACT_START_CRYPTO_ERASE			= 4,
};

/**
 * enum nvme_dst_stc -
 * @NVME_DST_STC_SHORT:
 * @NVME_DST_STC_LONG:
 * @NVME_DST_STC_VS:
 * @NVME_DST_STC_ABORT:
 */
enum nvme_dst_stc {
	NVME_DST_STC_SHORT					= 0x1,
	NVME_DST_STC_LONG					= 0x2,
	NVME_DST_STC_VS						= 0xe,
	NVME_DST_STC_ABORT					= 0xf,
};

/**
 * enum nvme_virt_mgmt_act -
 * @NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC:
 * @NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL:
 * @NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL:
 * @NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL:
 */
enum nvme_virt_mgmt_act {
	NVME_VIRT_MGMT_ACT_PRIM_CTRL_FLEX_ALLOC			= 1,
	NVME_VIRT_MGMT_ACT_OFFLINE_SEC_CTRL			= 7,
	NVME_VIRT_MGMT_ACT_ASSIGN_SEC_CTRL			= 8,
	NVME_VIRT_MGMT_ACT_ONLINE_SEC_CTRL			= 9,
};

/**
 * enum nvme_virt_mgmt_rt -
 * @NVME_VIRT_MGMT_RT_VQ_RESOURCE:
 * @NVME_VIRT_MGMT_RT_VI_RESOURCE:
 */
enum nvme_virt_mgmt_rt {
	NVME_VIRT_MGMT_RT_VQ_RESOURCE				= 0,
	NVME_VIRT_MGMT_RT_VI_RESOURCE				= 1,
};

/**
 * enum nvme_ns_write_protect -
 * @NVME_NS_WP_CFG_NONE
 * @NVME_NS_WP_CFG_PROTECT
 * @NVME_NS_WP_CFG_PROTECT_POWER_CYCLE
 * @NVME_NS_WP_CFG_PROTECT_PERMANENT
 */
enum nvme_ns_write_protect_cfg {
	NVME_NS_WP_CFG_NONE					= 0,
	NVME_NS_WP_CFG_PROTECT					= 1,
	NVME_NS_WP_CFG_PROTECT_POWER_CYCLE			= 2,
	NVME_NS_WP_CFG_PROTECT_PERMANENT			= 3,
};

/**
 * enum nvme_log_ana_lsp -
 * @NVME_LOG_ANA_LSP_RGO_NAMESPACES:
 * @NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY:
 */
enum nvme_log_ana_lsp {
	NVME_LOG_ANA_LSP_RGO_NAMESPACES				= 0,
	NVME_LOG_ANA_LSP_RGO_GROUPS_ONLY			= 1,
};

/**
 * enum nvme_pevent_log_action -
 */
enum nvme_pevent_log_action {
	NVME_PEVENT_LOG_READ			= 0x0,
	NVME_PEVENT_LOG_EST_CTX_AND_READ	= 0x1,
	NVME_PEVENT_LOG_RELEASE_CTX		= 0x2,
};

/**
 * enum nvme_feat_tmpthresh_thsel -
 */
enum nvme_feat_tmpthresh_thsel {
	NVME_FEATURE_TEMPTHRESH_THSEL_OVER			= 0,
	NVME_FEATURE_TEMPTHRESH_THSEL_UNDER			= 1,
};

/**
 * enum nvme_features_async_event_config_flags -
 */
enum nvme_features_async_event_config_flags {
	NVME_FEATURE_AENCFG_SMART_CRIT_SPARE			= 1 << 0,
	NVME_FEATURE_AENCFG_SMART_CRIT_TEMPERATURE		= 1 << 1,
	NVME_FEATURE_AENCFG_SMART_CRIT_DEGRADED			= 1 << 2,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY		= 1 << 3,
	NVME_FEATURE_AENCFG_SMART_CRIT_VOLATILE_BACKUP		= 1 << 4,
	NVME_FEATURE_AENCFG_SMART_CRIT_READ_ONLY_PMR		= 1 << 5,
	NVME_FEATURE_AENCFG_NOTICE_NAMESPACE_ATTRIBUTES		= 1 << 8,
	NVME_FEATURE_AENCFG_NOTICE_FIRMWARE_ACTIVATION		= 1 << 9,
	NVME_FEATURE_AENCFG_NOTICE_TELEMETRY_LOG		= 1 << 10,
	NVME_FEATURE_AENCFG_NOTICE_ANA_CHANGE			= 1 << 11,
	NVME_FEATURE_AENCFG_NOTICE_PL_EVENT			= 1 << 12,
	NVME_FEATURE_AENCFG_NOTICE_LBA_STATUS			= 1 << 13,
	NVME_FEATURE_AENCFG_NOTICE_EG_EVENT			= 1 << 14,
	NVME_FEATURE_AENCFG_NOTICE_DISCOVERY_CHANGE		= 1 << 31,
};

/**
 * enum nvme_feat_plm_window_select -
 */
enum nvme_feat_plm_window_select {
	NVME_FEATURE_PLM_DTWIN					= 1,
	NVME_FEATURE_PLM_NDWIN					= 2,
};

/**
 *
 */
enum nvme_feat_resv_notify_flags {
	NVME_FEAT_RESV_NOTIFY_REGPRE		= 1 << 1,
	NVME_FEAT_RESV_NOTIFY_RESREL		= 1 << 2,
	NVME_FEAT_RESV_NOTIFY_RESPRE		= 1 << 3,
};

/**
 * enum nvme_feat_ns_wp_cfg_state -
 * @NVME_FEAT_NS_NO_WRITE_PROTECT:
 * @NVME_FEAT_NS_WRITE_PROTECT:
 * @NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE:
 * @NVME_FEAT_NS_WRITE_PROTECT_PERMANENT:
 */
enum nvme_feat_nswpcfg_state {
	NVME_FEAT_NS_NO_WRITE_PROTECT 		= 0,
	NVME_FEAT_NS_WRITE_PROTECT		= 1,
	NVME_FEAT_NS_WRITE_PROTECT_PWR_CYCLE	= 2,
	NVME_FEAT_NS_WRITE_PROTECT_PERMANENT	= 3,
};

/**
 * enum nvme_fctype -
 * @nvme_fabrics_type_property_set:
 * @nvme_fabrics_type_connect:
 * @nvme_fabrics_type_property_get:
 * @nvme_fabrics_type_auth_send:
 * @nvme_fabrics_type_auth_receive:
 * @nvme_fabrics_type_disconnect:
 */
enum nvme_fctype {
	nvme_fabrics_type_property_set		= 0x00,
	nvme_fabrics_type_connect		= 0x01,
	nvme_fabrics_type_property_get		= 0x04,
	nvme_fabrics_type_auth_send		= 0x05,
	nvme_fabrics_type_auth_receive		= 0x06,
	nvme_fabrics_type_disconnect		= 0x08,
};

/**
 * enum nvme_io_opcode -
 * @nvme_cmd_flush:
 * @nvme_cmd_write:
 * @nvme_cmd_read:
 * @nvme_cmd_write_uncor:
 * @nvme_cmd_compare:
 * @nvme_cmd_write_zeroes:
 * @nvme_cmd_dsm:
 * @nvme_cmd_verify:
 * @nvme_cmd_resv_register:
 * @nvme_cmd_resv_report:
 * @nvme_cmd_resv_acquire:
 * @nvme_cmd_resv_release:
 */
enum nvme_io_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_uncor	= 0x04,
	nvme_cmd_compare	= 0x05,
	nvme_cmd_write_zeroes	= 0x08,
	nvme_cmd_dsm		= 0x09,
	nvme_cmd_verify		= 0x0c,
	nvme_cmd_resv_register	= 0x0d,
	nvme_cmd_resv_report	= 0x0e,
	nvme_cmd_resv_acquire	= 0x11,
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_copy		= 0x19,
	nvme_zns_cmd_mgmt_send	= 0x79,
	nvme_zns_cmd_mgmt_recv	= 0x7a,
	nvme_zns_cmd_append	= 0x7d,
};

/**
 * enum nvme_io_control_flags -
 * @NVME_IO_DTYPE_STREAMS:
 * @NVME_IO_DEAC:
 * @NVME_IO_ZNS_APPEND_PIREMAP:
 * @NVME_IO_PRINFO_PRCHK_REF:
 * @NVME_IO_PRINFO_PRCHK_APP:
 * @NVME_IO_PRINFO_PRCHK_GUARD:
 * @NVME_IO_PRINFO_PRACT:
 * @NVME_IO_FUA:
 * @NVME_IO_LR:
 */
enum nvme_io_control_flags {
	NVME_IO_DTYPE_STREAMS		= 1 << 4,
	NVME_IO_DEAC			= 1 << 9,
	NVME_IO_ZNS_APPEND_PIREMAP	= 1 << 9,
	NVME_IO_PRINFO_PRCHK_REF	= 1 << 10,
	NVME_IO_PRINFO_PRCHK_APP	= 1 << 11,
	NVME_IO_PRINFO_PRCHK_GUARD	= 1 << 12,
	NVME_IO_PRINFO_PRACT		= 1 << 13,
	NVME_IO_FUA			= 1 << 14,
	NVME_IO_LR			= 1 << 15,
};

/**
 * enum nvme_io_dsm_flag -
 * @NVME_IO_DSM_FREQ_UNSPEC:
 * @NVME_IO_DSM_FREQ_TYPICAL:
 * @NVME_IO_DSM_FREQ_RARE:
 * @NVME_IO_DSM_FREQ_READS:
 * @NVME_IO_DSM_FREQ_WRITES:
 * @NVME_IO_DSM_FREQ_RW:
 * @NVME_IO_DSM_FREQ_ONCE:
 * @NVME_IO_DSM_FREQ_PREFETCH:
 * @NVME_IO_DSM_FREQ_TEMP:
 * @NVME_IO_DSM_LATENCY_NONE:
 * @NVME_IO_DSM_LATENCY_IDLE:
 * @NVME_IO_DSM_LATENCY_NORM:
 * @NVME_IO_DSM_LATENCY_LOW:
 * @NVME_IO_DSM_SEQ_REQ:
 * @NVME_IO_DSM_COMPRESSED:
 */
enum nvme_io_dsm_flags {
	NVME_IO_DSM_FREQ_UNSPEC		= 0,
	NVME_IO_DSM_FREQ_TYPICAL	= 1,
	NVME_IO_DSM_FREQ_RARE		= 2,
	NVME_IO_DSM_FREQ_READS		= 3,
	NVME_IO_DSM_FREQ_WRITES		= 4,
	NVME_IO_DSM_FREQ_RW		= 5,
	NVME_IO_DSM_FREQ_ONCE		= 6,
	NVME_IO_DSM_FREQ_PREFETCH	= 7,
	NVME_IO_DSM_FREQ_TEMP		= 8,
	NVME_IO_DSM_LATENCY_NONE	= 0 << 4,
	NVME_IO_DSM_LATENCY_IDLE	= 1 << 4,
	NVME_IO_DSM_LATENCY_NORM	= 2 << 4,
	NVME_IO_DSM_LATENCY_LOW		= 3 << 4,
	NVME_IO_DSM_SEQ_REQ		= 1 << 6,
	NVME_IO_DSM_COMPRESSED		= 1 << 7,
};

/**
 * enum nvme_dsm_attributes -
 * @NVME_DSMGMT_IDR:
 * @NVME_DSMGMT_IDW:
 * @NVME_DSMGMT_AD:
 */
enum nvme_dsm_attributes {
	NVME_DSMGMT_IDR			= 1 << 0,
	NVME_DSMGMT_IDW			= 1 << 1,
	NVME_DSMGMT_AD			= 1 << 2,
};

/**
 * enum nvme_resv_rtype -
 * @NVME_RESERVATION_RTYPE_WE:
 * @NVME_RESERVATION_RTYPE_EA:
 * @NVME_RESERVATION_RTYPE_WERO:
 * @NVME_RESERVATION_RTYPE_EARO:
 * @NVME_RESERVATION_RTYPE_WEAR:
 * @NVME_RESERVATION_RTYPE_EAAR:
 */
enum nvme_resv_rtype {
	NVME_RESERVATION_RTYPE_WE	= 1,
	NVME_RESERVATION_RTYPE_EA	= 2,
	NVME_RESERVATION_RTYPE_WERO	= 3,
	NVME_RESERVATION_RTYPE_EARO	= 4,
	NVME_RESERVATION_RTYPE_WEAR	= 5,
	NVME_RESERVATION_RTYPE_EAAR	= 6,
};

/**
 * enum nvme_resv_racqa -
 * @NVME_RESERVATION_RACQA_ACQUIRE:
 * @NVME_RESERVATION_RACQA_PREEMPT:
 * @NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT:
 */
enum nvme_resv_racqa {
	NVME_RESERVATION_RACQA_ACQUIRE			= 0,
	NVME_RESERVATION_RACQA_PREEMPT			= 1,
	NVME_RESERVATION_RACQA_PREEMPT_AND_ABORT	= 2,
};

/**
 * enum nvme_resv_rrega -
 * @NVME_RESERVATION_RREGA_REGISTER_KEY:
 * @NVME_RESERVATION_RREGA_UNREGISTER_KEY:
 * @NVME_RESERVATION_RREGA_REPLACE_KEY:
 */
enum nvme_resv_rrega {
	NVME_RESERVATION_RREGA_REGISTER_KEY		= 0,
	NVME_RESERVATION_RREGA_UNREGISTER_KEY		= 1,
	NVME_RESERVATION_RREGA_REPLACE_KEY		= 2,
};

/**
 * enum nvme_resv_cptpl -
 * @NVME_RESERVATION_CPTPL_NO_CHANGE:
 * @NVME_RESERVATION_CPTPL_CLEAR:
 * @NVME_RESERVATION_CPTPL_PERSIST:
 */
enum nvme_resv_cptpl {
	NVME_RESERVATION_CPTPL_NO_CHANGE		= 0,
	NVME_RESERVATION_CPTPL_CLEAR			= 2,
	NVME_RESERVATION_CPTPL_PERSIST			= 3,
};

/**
 * enum nvme_resv_rrela -
 * @NVME_RESERVATION_RRELA_RELEASE:
 * @NVME_RESERVATION_RRELA_CLEAR:
 */
enum nvme_resv_rrela {
	NVME_RESERVATION_RRELA_RELEASE			= 0,
	NVME_RESERVATION_RRELA_CLEAR			= 1
};

enum nvme_zns_send_action {
	NVME_ZNS_ZSA_CLOSE		= 0x1,
	NVME_ZNS_ZSA_FINISH		= 0x2,
	NVME_ZNS_ZSA_OPEN		= 0x3,
	NVME_ZNS_ZSA_RESET		= 0x4,
	NVME_ZNS_ZSA_OFFLINE		= 0x5,
	NVME_ZNS_ZSA_SET_DESC_EXT	= 0x10,
};

/**
 * enum nvme_zns_recv_action -
 */
enum nvme_zns_recv_action {
	NVME_ZNS_ZRA_REPORT_ZONES		= 0x0,
	NVME_ZNS_ZRA_EXTENDED_REPORT_ZONES	= 0x1,
};

/**
 * enum nvme_zns_report_options -
 */
enum nvme_zns_report_options {
	NVME_ZNS_ZRAS_REPORT_ALL		= 0x0,
	NVME_ZNS_ZRAS_REPORT_EMPTY		= 0x1,
	NVME_ZNS_ZRAS_REPORT_IMPL_OPENED	= 0x2,
	NVME_ZNS_ZRAS_REPORT_EXPL_OPENED	= 0x3,
	NVME_ZNS_ZRAS_REPORT_CLOSED		= 0x4,
	NVME_ZNS_ZRAS_REPORT_FULL		= 0x5,
	NVME_ZNS_ZRAS_REPORT_READ_ONLY		= 0x6,
	NVME_ZNS_ZRAS_REPORT_OFFLINE		= 0x7,
};

#endif /* _LIBNVME_CMD_H */
