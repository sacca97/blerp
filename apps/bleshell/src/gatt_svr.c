/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "os/mynewt.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "bsp/bsp.h"
#include "console/console.h"
#include "host/ble_att.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_hs_mbuf.h"
#include "host/ble_uuid.h"
#include "btshell.h"

#define BTSHELL_HID_PROFILE_KEYBOARD 1
#define BTSHELL_HID_PROFILE_MOUSE 2

#if (MYNEWT_VAL(BTSHELL_HID_PROFILE) != BTSHELL_HID_PROFILE_KEYBOARD) && \
    (MYNEWT_VAL(BTSHELL_HID_PROFILE) != BTSHELL_HID_PROFILE_MOUSE)
#error "Invalid BTSHELL_HID_PROFILE value; use 1 (keyboard) or 2 (mouse)"
#endif

#if MYNEWT_VAL(BTSHELL_HID_PROFILE) == BTSHELL_HID_PROFILE_MOUSE
#define BTSHELL_HID_IS_MOUSE 1
#else
#define BTSHELL_HID_IS_MOUSE 0
#endif

#define GATT_SVR_ARG(attr_id) ((void *) (uintptr_t) (attr_id))

#define UUID_DIS 0x180A
#define UUID_BAS 0x180F
#define UUID_HID 0x1812

#define UUID_BOOT_MOUSE_INPUT_REPORT 0x2A33
#define UUID_REPORT_REFERENCE 0x2908

enum gatt_svr_attr_id {
    GATT_SVR_ATTR_PNP_ID,
#if BTSHELL_HID_IS_MOUSE
    GATT_SVR_ATTR_MANUFACTURER_NAME,
    GATT_SVR_ATTR_MODEL_NUMBER,
    GATT_SVR_ATTR_SERIAL_NUMBER,
    GATT_SVR_ATTR_FIRMWARE_REVISION,
    GATT_SVR_ATTR_SOFTWARE_REVISION,
#endif
    GATT_SVR_ATTR_BATTERY_LEVEL,
    GATT_SVR_ATTR_PROTOCOL_MODE,
    GATT_SVR_ATTR_REPORT_MAP,
    GATT_SVR_ATTR_HID_INFORMATION,
    GATT_SVR_ATTR_HID_CONTROL_POINT,
#if BTSHELL_HID_IS_MOUSE
    GATT_SVR_ATTR_BOOT_MOUSE_INPUT_REPORT,
#endif
    GATT_SVR_ATTR_REPORT_INPUT_0,
#if BTSHELL_HID_IS_MOUSE
    GATT_SVR_ATTR_REPORT_INPUT_1,
    GATT_SVR_ATTR_REPORT_OUTPUT,
#endif
    GATT_SVR_ATTR_REPORT_REFERENCE_0,
#if BTSHELL_HID_IS_MOUSE
    GATT_SVR_ATTR_REPORT_REFERENCE_1,
    GATT_SVR_ATTR_REPORT_REFERENCE_2,
#endif
};

static uint8_t gatt_svr_battery_level;
static uint8_t gatt_svr_hid_protocol_mode = 0x01;
static uint8_t gatt_svr_hid_control_point = 0x00;
static bool gatt_svr_hid_input_ready;

static uint16_t gatt_svr_battery_level_handle;
static uint16_t gatt_svr_hid_report_handle;

#if BTSHELL_HID_IS_MOUSE
static uint16_t gatt_svr_hid_boot_mouse_input_report_handle;
static uint16_t gatt_svr_hid_report_input_1_handle;
static uint16_t gatt_svr_hid_report_output_handle;
#endif

static uint8_t gatt_svr_hid_report_input_0[BTSHELL_HID_IS_MOUSE ? 7 : 8];

#if BTSHELL_HID_IS_MOUSE
static uint8_t gatt_svr_hid_boot_mouse_input_report[4];
static uint8_t gatt_svr_hid_report_input_1[7];
static uint8_t gatt_svr_hid_report_output[4];
#endif

#if BTSHELL_HID_IS_MOUSE
static const uint8_t gatt_svr_mouse_report_map[] = {
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, 0x09, 0x01, 0xa1, 0x00,
    0x95, 0x10, 0x75, 0x01, 0x15, 0x00, 0x25, 0x01, 0x05, 0x09, 0x19, 0x01,
    0x29, 0x10, 0x81, 0x02, 0x05, 0x01, 0x16, 0x01, 0xf8, 0x26, 0xff, 0x07,
    0x75, 0x0c, 0x95, 0x02, 0x09, 0x30, 0x09, 0x31, 0x81, 0x06, 0x15, 0x81,
    0x25, 0x7f, 0x75, 0x08, 0x95, 0x01, 0x09, 0x38, 0x81, 0x06, 0x95, 0x01,
    0x05, 0x0c, 0x0a, 0x38, 0x02, 0x81, 0x06, 0xc0, 0xc0, 0x06, 0x43, 0xff,
    0x0a, 0x02, 0x02, 0xa1, 0x01, 0x85, 0x11, 0x75, 0x08, 0x95, 0x13, 0x15,
    0x00, 0x26, 0xff, 0x00, 0x09, 0x02, 0x81, 0x00, 0x09, 0x02, 0x91, 0x00,
    0xc0,
};
static const uint8_t gatt_svr_hid_information[] = {0x11, 0x01, 0x00, 0x03};
static const uint8_t gatt_svr_dis_pnp_id[] = {0x02, 0x6d, 0x04, 0x37, 0xb0, 0x03, 0x00};
static const uint8_t gatt_svr_dis_manufacturer_name[] = "Logitech";
static const uint8_t gatt_svr_dis_model_number[] = "MX Anywhere 3S";
static const uint8_t gatt_svr_dis_serial_number[] = "1234567890";
static const uint8_t gatt_svr_dis_firmware_revision[] = "RBM23.00_0001";
static const uint8_t gatt_svr_dis_software_revision[] = "1.0";
static const uint8_t gatt_svr_report_reference_0[] = {0x02, 0x01};
static const uint8_t gatt_svr_report_reference_1[] = {0x11, 0x01};
static const uint8_t gatt_svr_report_reference_2[] = {0x11, 0x02};
#else
static const uint8_t gatt_svr_keyboard_report_map[] = {
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01,
    0x75, 0x08, 0x81, 0x01, 0x05, 0x07, 0x19, 0x00, 0x29, 0xff, 0x15, 0x00,
    0x25, 0xff, 0x95, 0x06, 0x75, 0x08, 0x81, 0x00, 0xc0,
};
static const uint8_t gatt_svr_hid_information[] = {0x11, 0x01, 0x00, 0x02};
static const uint8_t gatt_svr_dis_pnp_id[] = {0x02, 0x34, 0x12, 0x23, 0xb0, 0x13, 0x00};
static const uint8_t gatt_svr_report_reference_0[] = {0x00, 0x01};
#endif

static int gatt_svr_access_dis(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg);
static int gatt_svr_access_battery(uint16_t conn_handle, uint16_t attr_handle,
                                   struct ble_gatt_access_ctxt *ctxt, void *arg);
static int gatt_svr_access_hid(uint16_t conn_handle, uint16_t attr_handle,
                               struct ble_gatt_access_ctxt *ctxt, void *arg);
static int gatt_svr_notify_value(uint16_t conn_handle, uint16_t attr_handle,
                                 const void *value, uint16_t value_len);

static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(UUID_DIS),
        .characteristics = (struct ble_gatt_chr_def[]) {{
#if BTSHELL_HID_IS_MOUSE
            .uuid = BLE_UUID16_DECLARE(0x2a29),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_MANUFACTURER_NAME),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a24),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_MODEL_NUMBER),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a25),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_SERIAL_NUMBER),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a26),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_FIRMWARE_REVISION),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a28),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_SOFTWARE_REVISION),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
#endif
            .uuid = BLE_UUID16_DECLARE(0x2a50),
            .access_cb = gatt_svr_access_dis,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_PNP_ID),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            0,
        }},
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(UUID_BAS),
        .characteristics = (struct ble_gatt_chr_def[]) {{
            .uuid = BLE_UUID16_DECLARE(0x2a19),
            .access_cb = gatt_svr_access_battery,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_BATTERY_LEVEL),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &gatt_svr_battery_level_handle,
        }, {
            0,
        }},
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(UUID_HID),
        .characteristics = (struct ble_gatt_chr_def[]) {{
#if BTSHELL_HID_IS_MOUSE
            .uuid = BLE_UUID16_DECLARE(0x2a4a),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_HID_INFORMATION),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(UUID_BOOT_MOUSE_INPUT_REPORT),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_BOOT_MOUSE_INPUT_REPORT),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &gatt_svr_hid_boot_mouse_input_report_handle,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4b),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_MAP),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4d),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_INPUT_0),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &gatt_svr_hid_report_handle,
            .descriptors = (struct ble_gatt_dsc_def[]) {{
                .uuid = BLE_UUID16_DECLARE(UUID_REPORT_REFERENCE),
                .att_flags = BLE_ATT_F_READ,
                .access_cb = gatt_svr_access_hid,
                .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_REFERENCE_0),
            }, {
                0,
            }},
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4d),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_INPUT_1),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
            .val_handle = &gatt_svr_hid_report_input_1_handle,
            .descriptors = (struct ble_gatt_dsc_def[]) {{
                .uuid = BLE_UUID16_DECLARE(UUID_REPORT_REFERENCE),
                .att_flags = BLE_ATT_F_READ,
                .access_cb = gatt_svr_access_hid,
                .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_REFERENCE_1),
            }, {
                0,
            }},
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4d),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_OUTPUT),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                     BLE_GATT_CHR_F_WRITE_NO_RSP,
            .val_handle = &gatt_svr_hid_report_output_handle,
            .descriptors = (struct ble_gatt_dsc_def[]) {{
                .uuid = BLE_UUID16_DECLARE(UUID_REPORT_REFERENCE),
                .att_flags = BLE_ATT_F_READ,
                .access_cb = gatt_svr_access_hid,
                .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_REFERENCE_2),
            }, {
                0,
            }},
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4c),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_HID_CONTROL_POINT),
            .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4e),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_PROTOCOL_MODE),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
#else
            .uuid = BLE_UUID16_DECLARE(0x2a4e),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_PROTOCOL_MODE),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE |
                     BLE_GATT_CHR_F_READ_ENC | BLE_GATT_CHR_F_WRITE_ENC,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4b),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_MAP),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4a),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_HID_INFORMATION),
            .flags = BLE_GATT_CHR_F_READ,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4c),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_HID_CONTROL_POINT),
            .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP |
                     BLE_GATT_CHR_F_WRITE_ENC,
        }, {
            .uuid = BLE_UUID16_DECLARE(0x2a4d),
            .access_cb = gatt_svr_access_hid,
            .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_INPUT_0),
            .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY |
                     BLE_GATT_CHR_F_READ_ENC,
            .val_handle = &gatt_svr_hid_report_handle,
            .descriptors = (struct ble_gatt_dsc_def[]) {{
                .uuid = BLE_UUID16_DECLARE(UUID_REPORT_REFERENCE),
                .att_flags = BLE_ATT_F_READ,
                .access_cb = gatt_svr_access_hid,
                .arg = GATT_SVR_ARG(GATT_SVR_ATTR_REPORT_REFERENCE_0),
            }, {
                0,
            }},
#endif
        }, {
            0,
        }},
    },
    {
        0,
    },
};

static int
gatt_svr_chr_write(struct os_mbuf *om, uint16_t min_len, uint16_t max_len,
                   void *dst, uint16_t *len)
{
    uint16_t om_len;
    int rc;

    om_len = OS_MBUF_PKTLEN(om);
    if (om_len < min_len || om_len > max_len) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    rc = ble_hs_mbuf_to_flat(om, dst, max_len, len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static int
gatt_svr_attr_read(struct os_mbuf *om, const void *src, uint16_t len)
{
    int rc;

    rc = os_mbuf_append(om, src, len);
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static void
gatt_svr_notify_battery_level(uint16_t conn_handle)
{
    int rc;

    if (conn_handle == BLE_HS_CONN_HANDLE_NONE || gatt_svr_battery_level_handle == 0) {
        return;
    }

    rc = gatt_svr_notify_value(conn_handle, gatt_svr_battery_level_handle,
                               &gatt_svr_battery_level,
                               sizeof gatt_svr_battery_level);
    if (rc != 0) {
        MODLOG_DFLT(DEBUG, "battery notify failed; rc=%d\n", rc);
    }
}

static int
gatt_svr_notify_value(uint16_t conn_handle, uint16_t attr_handle,
                      const void *value, uint16_t value_len)
{
    struct os_mbuf *om;
    int rc;

    if (conn_handle == BLE_HS_CONN_HANDLE_NONE || attr_handle == 0 || value == NULL) {
        return BLE_HS_EINVAL;
    }

    om = ble_hs_mbuf_from_flat(value, value_len);
    if (om == NULL) {
        return BLE_HS_ENOMEM;
    }

    rc = ble_gatts_notify_custom(conn_handle, attr_handle, om);
    if (rc != 0) {
        MODLOG_DFLT(DEBUG, "notify failed; attr_handle=%u rc=%d\n", attr_handle, rc);
    }

    return rc;
}

static int
gatt_svr_access_dis(uint16_t conn_handle, uint16_t attr_handle,
                    struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint32_t attr_id;

    (void) conn_handle;
    (void) attr_handle;
    attr_id = (uintptr_t) arg;

    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    switch (attr_id) {
    case GATT_SVR_ATTR_PNP_ID:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_pnp_id, sizeof gatt_svr_dis_pnp_id);
#if BTSHELL_HID_IS_MOUSE
    case GATT_SVR_ATTR_MANUFACTURER_NAME:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_manufacturer_name,
                                  sizeof gatt_svr_dis_manufacturer_name - 1);
    case GATT_SVR_ATTR_MODEL_NUMBER:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_model_number,
                                  sizeof gatt_svr_dis_model_number - 1);
    case GATT_SVR_ATTR_SERIAL_NUMBER:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_serial_number,
                                  sizeof gatt_svr_dis_serial_number - 1);
    case GATT_SVR_ATTR_FIRMWARE_REVISION:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_firmware_revision,
                                  sizeof gatt_svr_dis_firmware_revision - 1);
    case GATT_SVR_ATTR_SOFTWARE_REVISION:
        return gatt_svr_attr_read(ctxt->om, gatt_svr_dis_software_revision,
                                  sizeof gatt_svr_dis_software_revision - 1);
#endif
    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

static int
gatt_svr_access_battery(uint16_t conn_handle, uint16_t attr_handle,
                        struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void) attr_handle;

    if ((uintptr_t) arg != GATT_SVR_ATTR_BATTERY_LEVEL) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
        return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    }

    gatt_svr_notify_battery_level(conn_handle);
    return gatt_svr_attr_read(ctxt->om, &gatt_svr_battery_level, sizeof gatt_svr_battery_level);
}

static int
gatt_svr_access_hid(uint16_t conn_handle, uint16_t attr_handle,
                    struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    uint32_t attr_id;

    (void) conn_handle;
    (void) attr_handle;
    attr_id = (uintptr_t) arg;

    switch (attr_id) {
    case GATT_SVR_ATTR_PROTOCOL_MODE:
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            return gatt_svr_attr_read(ctxt->om, &gatt_svr_hid_protocol_mode,
                                      sizeof gatt_svr_hid_protocol_mode);
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            return gatt_svr_chr_write(ctxt->om, sizeof gatt_svr_hid_protocol_mode,
                                      sizeof gatt_svr_hid_protocol_mode,
                                      &gatt_svr_hid_protocol_mode, NULL);
        }
        return BLE_ATT_ERR_UNLIKELY;

    case GATT_SVR_ATTR_REPORT_MAP:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
#if BTSHELL_HID_IS_MOUSE
        return gatt_svr_attr_read(ctxt->om, gatt_svr_mouse_report_map,
                                  sizeof gatt_svr_mouse_report_map);
#else
        return gatt_svr_attr_read(ctxt->om, gatt_svr_keyboard_report_map,
                                  sizeof gatt_svr_keyboard_report_map);
#endif

    case GATT_SVR_ATTR_HID_INFORMATION:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_hid_information,
                                  sizeof gatt_svr_hid_information);

    case GATT_SVR_ATTR_HID_CONTROL_POINT:
        if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
            return BLE_ATT_ERR_READ_NOT_PERMITTED;
        }
        return gatt_svr_chr_write(ctxt->om, sizeof gatt_svr_hid_control_point,
                                  sizeof gatt_svr_hid_control_point,
                                  &gatt_svr_hid_control_point, NULL);

#if BTSHELL_HID_IS_MOUSE
    case GATT_SVR_ATTR_BOOT_MOUSE_INPUT_REPORT:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_hid_boot_mouse_input_report,
                                  sizeof gatt_svr_hid_boot_mouse_input_report);
#endif

    case GATT_SVR_ATTR_REPORT_INPUT_0:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_hid_report_input_0,
                                  sizeof gatt_svr_hid_report_input_0);

#if BTSHELL_HID_IS_MOUSE
    case GATT_SVR_ATTR_REPORT_INPUT_1:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_CHR) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_hid_report_input_1,
                                  sizeof gatt_svr_hid_report_input_1);

    case GATT_SVR_ATTR_REPORT_OUTPUT:
        if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
            return gatt_svr_attr_read(ctxt->om, gatt_svr_hid_report_output,
                                      sizeof gatt_svr_hid_report_output);
        }
        if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
            return gatt_svr_chr_write(ctxt->om, 0, sizeof gatt_svr_hid_report_output,
                                      gatt_svr_hid_report_output, NULL);
        }
        return BLE_ATT_ERR_UNLIKELY;
#endif

    case GATT_SVR_ATTR_REPORT_REFERENCE_0:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_report_reference_0,
                                  sizeof gatt_svr_report_reference_0);

#if BTSHELL_HID_IS_MOUSE
    case GATT_SVR_ATTR_REPORT_REFERENCE_1:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_report_reference_1,
                                  sizeof gatt_svr_report_reference_1);

    case GATT_SVR_ATTR_REPORT_REFERENCE_2:
        if (ctxt->op != BLE_GATT_ACCESS_OP_READ_DSC) {
            return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
        }
        return gatt_svr_attr_read(ctxt->om, gatt_svr_report_reference_2,
                                  sizeof gatt_svr_report_reference_2);
#endif

    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

void
gatt_svr_on_subscribe(uint16_t conn_handle, uint16_t attr_handle, uint8_t cur_notify,
                      uint8_t cur_indicate)
{
    (void) cur_indicate;

    if (attr_handle == gatt_svr_hid_report_handle) {
        gatt_svr_hid_input_ready = cur_notify != 0;
        if (gatt_svr_hid_input_ready) {
            gatt_svr_notify_battery_level(conn_handle);
        }
    }
}

void
gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    char buf[BLE_UUID_STR_LEN];

    switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
        MODLOG_DFLT(DEBUG, "registered service %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                    ctxt->svc.handle);
        break;

    case BLE_GATT_REGISTER_OP_CHR:
        MODLOG_DFLT(DEBUG, "registering characteristic %s with "
                           "def_handle=%d val_handle=%d\n",
                    ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                    ctxt->chr.def_handle,
                    ctxt->chr.val_handle);
        break;

    case BLE_GATT_REGISTER_OP_DSC:
        MODLOG_DFLT(DEBUG, "registering descriptor %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                    ctxt->dsc.handle);
        break;

    default:
        assert(0);
        break;
    }
}

void
gatt_svr_print_svcs(void)
{
    ble_gatts_show_local();
}

int
gatt_svr_send_hid_report(uint16_t conn_handle, const uint8_t *report,
                         uint16_t report_len)
{
    if (report == NULL || report_len != sizeof gatt_svr_hid_report_input_0) {
        return BLE_HS_EINVAL;
    }

    if (gatt_svr_hid_report_handle == 0) {
        return BLE_HS_EINVAL;
    }

    if (!gatt_svr_hid_input_ready) {
        MODLOG_DFLT(DEBUG, "HID input report sent before CCCD enable\n");
    }

    memcpy(gatt_svr_hid_report_input_0, report, sizeof gatt_svr_hid_report_input_0);

    return gatt_svr_notify_value(conn_handle, gatt_svr_hid_report_handle,
                                 gatt_svr_hid_report_input_0,
                                 sizeof gatt_svr_hid_report_input_0);
}

int
gatt_svr_send_mouse_report(uint16_t conn_handle, uint16_t buttons,
                           int16_t dx, int16_t dy, int8_t wheel, int8_t pan)
{
#if !BTSHELL_HID_IS_MOUSE
    (void) conn_handle;
    (void) buttons;
    (void) dx;
    (void) dy;
    (void) wheel;
    (void) pan;
    return BLE_HS_ENOTSUP;
#else
    uint8_t report[7];
    uint16_t x_u12;
    uint16_t y_u12;
    uint32_t xy_packed;

    if (dx < -2047) {
        dx = -2047;
    } else if (dx > 2047) {
        dx = 2047;
    }

    if (dy < -2047) {
        dy = -2047;
    } else if (dy > 2047) {
        dy = 2047;
    }

    x_u12 = (uint16_t)dx & 0x0fff;
    y_u12 = (uint16_t)dy & 0x0fff;
    xy_packed = x_u12 | ((uint32_t)y_u12 << 12);

    report[0] = buttons & 0xff;
    report[1] = buttons >> 8;
    report[2] = xy_packed & 0xff;
    report[3] = (xy_packed >> 8) & 0xff;
    report[4] = (xy_packed >> 16) & 0xff;
    report[5] = (uint8_t)wheel;
    report[6] = (uint8_t)pan;

    return gatt_svr_send_hid_report(conn_handle, report, sizeof report);
#endif
}

int
gatt_svr_mouse_move(uint16_t conn_handle, int16_t dx, int16_t dy)
{
    return gatt_svr_send_mouse_report(conn_handle, 0, dx, dy, 0, 0);
}

int
gatt_svr_mouse_click(uint16_t conn_handle, uint8_t button, uint16_t hold_ms)
{
#if !BTSHELL_HID_IS_MOUSE
    (void) conn_handle;
    (void) button;
    (void) hold_ms;
    return BLE_HS_ENOTSUP;
#else
    uint16_t button_mask;
    int rc;

    if (button < 1 || button > 3) {
        return BLE_HS_EINVAL;
    }

    button_mask = 1U << (button - 1);

    rc = gatt_svr_send_mouse_report(conn_handle, button_mask, 0, 0, 0, 0);
    if (rc != 0) {
        return rc;
    }

    if (hold_ms > 0) {
        os_time_delay(os_time_ms_to_ticks32(hold_ms));
    }

    return gatt_svr_send_mouse_report(conn_handle, 0, 0, 0, 0, 0);
#endif
}

int
gatt_svr_init(void)
{
    int rc;

    gatt_svr_battery_level = rand() % 101;
    gatt_svr_hid_input_ready = false;

    rc = ble_gatts_count_cfg(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(gatt_svr_svcs);
    return rc;
}
