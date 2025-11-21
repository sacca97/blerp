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

#include <assert.h>
#include <string.h>

#include "bsp/bsp.h"
#include "btshell.h"
#include "console/console.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"

/* 0000xxxx-8c26-476f-89a7-a108033a69c7 */
#define PTS_UUID_DECLARE(uuid16)                                              \
  ((const ble_uuid_t *)(&(ble_uuid128_t)BLE_UUID128_INIT(                     \
      0xc7, 0x69, 0x3a, 0x03, 0x08, 0xa1, 0xa7, 0x89, 0x6f, 0x47, 0x26, 0x8c, \
      uuid16, uuid16 >> 8, 0x00, 0x00)))

#define PTS_SVC 0x0001
#define PTS_CHR_READ 0x0002
#define PTS_CHR_WRITE 0x0003
#define PTS_CHR_RELIABLE_WRITE 0x0004
#define PTS_CHR_WRITE_NO_RSP 0x0005
#define PTS_CHR_READ_WRITE 0x0006
#define PTS_CHR_READ_WRITE_ENC 0x0007
#define PTS_CHR_READ_WRITE_AUTHEN 0x0008
#define PTS_DSC_READ 0x0009
#define PTS_DSC_WRITE 0x000a
#define PTS_DSC_READ_WRITE 0x000b
#define PTS_DSC_READ_WRITE_ENC 0x000c
#define PTS_DSC_READ_WRITE_AUTHEN 0x000d

#define PTS_LONG_SVC 0x0011
#define PTS_LONG_CHR_READ 0x0012
#define PTS_LONG_CHR_WRITE 0x0013
#define PTS_LONG_CHR_RELIABLE_WRITE 0x0014
#define PTS_LONG_CHR_READ_WRITE 0x0015
#define PTS_LONG_CHR_READ_WRITE_ALT 0x0016
#define PTS_LONG_CHR_READ_WRITE_ENC 0x0017
#define PTS_LONG_CHR_READ_WRITE_AUTHEN 0x0018
#define PTS_LONG_DSC_READ 0x0019
#define PTS_LONG_DSC_WRITE 0x001a
#define PTS_LONG_DSC_READ_WRITE 0x001b
#define PTS_LONG_DSC_READ_WRITE_ENC 0x001c
#define PTS_LONG_DSC_READ_WRITE_AUTHEN 0x001d

#define PTS_INC_SVC 0x001e
#define PTS_CHR_READ_WRITE_ALT 0x001f

/**
 * The vendor specific security test service consists of two characteristics:
 *     o random-number-generator: generates a random 32-bit number each time
 *       it is read.  This characteristic can only be read over an encrypted
 *       connection.
 *     o static-value: a single-byte characteristic that can always be read,
 *       but can only be written over an encrypted connection.
 */

/* 00010000-0000-1000-8000-011f2000046d */
static const ble_uuid128_t gatt_svr_svc_sec_mouse_main =
    BLE_UUID128_INIT(0x6d, 0x04, 0x00, 0x20, 0x1f, 0x01, 0x00, 0x80, 0x00, 0x10,
                     0x00, 0x00, 0x00, 0x00, 0x01, 0x00);

/* 00010001-0000-1000-8000-011f2000046d */
static const ble_uuid128_t gatt_svr_chr_sec_mouse_main =
    BLE_UUID128_INIT(0x6d, 0x04, 0x00, 0x20, 0x1f, 0x01, 0x00, 0x80, 0x00, 0x10,
                     0x00, 0x00, 0x01, 0x00, 0x01, 0x00);

/* 5c3a659e-897e-45e1-b016-007107c96df6 */
static const ble_uuid128_t gatt_svr_chr_sec_test_rand_uuid =
    BLE_UUID128_INIT(0xf6, 0x6d, 0xc9, 0x07, 0x71, 0x00, 0x16, 0xb0, 0xe1, 0x45,
                     0x7e, 0x89, 0x9e, 0x65, 0x3a, 0x5c);

/* 5c3a659e-897e-45e1-b016-007107c96df7 */
static const ble_uuid128_t gatt_svr_chr_sec_test_static_uuid =
    BLE_UUID128_INIT(0xf7, 0x6d, 0xc9, 0x07, 0x71, 0x00, 0x16, 0xb0, 0xe1, 0x45,
                     0x7e, 0x89, 0x9e, 0x65, 0x3a, 0x5c);

/* 5c3a659e-897e-45e1-b016-007107c96df8 */
static const ble_uuid128_t gatt_svr_chr_sec_test_static_auth_uuid =
    BLE_UUID128_INIT(0xf8, 0x6d, 0xc9, 0x07, 0x71, 0x00, 0x16, 0xb0, 0xe1, 0x45,
                     0x7e, 0x89, 0x9e, 0x65, 0x3a, 0x5c);

static int gatt_svr_chr_access_device_info(uint16_t conn_handle,
                                           uint16_t attr_handle,
                                           struct ble_gatt_access_ctxt *ctxt,
                                           void *arg);

int pnp_cb(uint16_t conn_handle, uint16_t attr_handle,
           struct ble_gatt_access_ctxt *ctxt, void *arg);

int report_descriptor_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg);

int report_cb(uint16_t conn_handle, uint16_t attr_handle,
              struct ble_gatt_access_ctxt *ctxt, void *arg);

uint16_t report_handle;
uint8_t report_buffer[4] = {0, 0, 0, 0};

const uint8_t hidReportMap[] = {
    0x05, 0x01,  // Usage Page (Generic Desktop)
    0x09, 0x02,  // Usage (Mouse)
    0xA1, 0x01,  // Collection (Application)
    0x85, 0x01,  // Report Id (1)
    0x09, 0x01,  //   Usage (Pointer)
    0xA1, 0x00,  //   Collection (Physical)
    0x05, 0x09,  //     Usage Page (Buttons)
    0x19, 0x01,  //     Usage Minimum (01) - Button 1
    0x29, 0x03,  //     Usage Maximum (03) - Button 3
    0x15, 0x00,  //     Logical Minimum (0)
    0x25, 0x01,  //     Logical Maximum (1)
    0x75, 0x01,  //     Report Size (1)
    0x95, 0x03,  //     Report Count (3)
    0x81, 0x02,  //     Input (Data, Variable, Absolute)
    0x75, 0x05,  //     Report Size (5)
    0x95, 0x01,  //     Report Count (1)
    0x81, 0x01,  //     Input (Constant) - Padding
    0x05, 0x01,  //     Usage Page (Generic Desktop)
    0x09, 0x30,  //     Usage (X)
    0x09, 0x31,  //     Usage (Y)
    0x09, 0x38,  //     Usage (Wheel)
    0x15, 0x81,  //     Logical Minimum (-127)
    0x25, 0x7F,  //     Logical Maximum (127)
    0x75, 0x08,  //     Report Size (8)
    0x95, 0x03,  //     Report Count (3)
    0x81, 0x06,  //     Input (Data, Variable, Relative)
    0xC0,        //   End Collection
    0xC0,        // End Collection
};

static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    {
        /*** Service: HID Profile */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(GATT_SVR_SVC_HID),
        .characteristics =
            (struct ble_gatt_chr_def[]){
                {
                    /* Characteristic: * HID Information */
                    .uuid = BLE_UUID16_DECLARE(GATT_SVR_CHR_HID_INFORMATION),
                    .access_cb = gatt_svr_chr_access_device_info,
                    .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
                },
                {
                    /* Characteristic: * HID Control Point */
                    .uuid = BLE_UUID16_DECLARE(GATT_SVR_CHR_HID_CONTROL_POINT),
                    .access_cb = gatt_svr_chr_access_device_info,
                    .flags = BLE_GATT_CHR_F_WRITE_NO_RSP,
                },
                {
                    /* Characteristic: * HID Report Map */
                    .uuid = BLE_UUID16_DECLARE(GATT_SVR_CHR_HID_REPORT_MAP),
                    .access_cb = gatt_svr_chr_access_device_info,
                    .flags = BLE_GATT_CHR_F_READ,
                },
                {/* Characteristic: Report */
                 .uuid = BLE_UUID16_DECLARE(GATT_SVR_CHR_HID_REPORT),
                 .access_cb = report_cb,
                 .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC |
                          BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE,
                 .val_handle = &report_handle,
                 .descriptors =
                     (struct ble_gatt_dsc_def[]){
                         {
                             .uuid = BLE_UUID16_DECLARE(
                                 GATT_UUID_REPORT_DESCRIPTOR),
                             .att_flags = BLE_ATT_F_READ,
                             .access_cb = report_descriptor_cb,
                             .min_key_size = 0,
                         },
                         {
                             0 /* No more descriptors */
                         }}},
                {
                    0, /* No more characteristics in this service. */
                }},
    },
    //     {/*** Service: Device Information */
    //  .type = BLE_GATT_SVC_TYPE_PRIMARY,
    //  .uuid = BLE_UUID16_DECLARE(BLE_SVC_DIS_UUID16),
    //  .characteristics =
    //      (struct ble_gatt_chr_def[]){
    //          {
    //              /* Characteristic: PnP ID */
    //              /* Only this is mandatory in HOGP */
    //              .uuid = BLE_UUID16_DECLARE(BLE_SVC_DIS_CHR_UUID16_PNP_ID),
    //              .access_cb = pnp_cb,
    //              .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
    //          },
    //     {0}}},
    {
        0, /* No more services. */
    },

};

int report_cb(uint16_t conn_handle, uint16_t attr_handle,
              struct ble_gatt_access_ctxt *ctxt, void *arg) {
  return 0;
  // uint16_t uuid16 = ble_uuid_u16(ctxt->chr->uuid);

  // int rc = os_mbuf_append(ctxt->om, report_buffer,
  //                         sizeof report_buffer);

  // return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

int report_descriptor_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg) {
  uint8_t reportDescriptor[2] = {0x01, 0x01};
  int rc = os_mbuf_append(ctxt->om, &reportDescriptor, sizeof reportDescriptor);

  return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

// int pnp_cb(uint16_t conn_handle, uint16_t attr_handle,
//            struct ble_gatt_access_ctxt *ctxt, void *arg) {
//     if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
//         uint8_t pnp[7] = {0x02, 0x6D, 0x04, 0x23, 0xB0, 0x13, 0x00};
//         int rc = os_mbuf_append(ctxt->om, &pnp, sizeof pnp);
//         return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
//     }
//     return BLE_ATT_ERR_REQ_NOT_SUPPORTED;
// }

static int gatt_svr_chr_access_device_info(uint16_t conn_handle,
                                           uint16_t attr_handle,
                                           struct ble_gatt_access_ctxt *ctxt,
                                           void *arg) {
  uint16_t uuid;
  int rc;

  uuid = ble_uuid_u16(ctxt->chr->uuid);

  if (uuid == GATT_SVR_CHR_HID_INFORMATION) {
    uint8_t hid_info[4] = {0x11, 0x01, 0x00, 0x03};
    rc = os_mbuf_append(ctxt->om, hid_info, sizeof hid_info);
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
  }

  if (uuid == GATT_SVR_CHR_HID_CONTROL_POINT) {
    return 0;
    uint8_t hid_ctrl = 0;
    rc = os_mbuf_append(ctxt->om, &hid_ctrl, sizeof hid_ctrl);
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
  }

  if (uuid == GATT_SVR_CHR_HID_REPORT_MAP) {
    // uint8_t report_map[5] = {0x05, 0x01, 0x09, 0x02, 0xA1};
    rc = os_mbuf_append(ctxt->om, hidReportMap, sizeof hidReportMap);
    return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
  }

  return BLE_ATT_ERR_UNLIKELY;
}

void gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg) {
  char buf[BLE_UUID_STR_LEN];

  switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
      MODLOG_DFLT(DEBUG, "registered service %s with handle=%d\n",
                  ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                  ctxt->svc.handle);
      break;

    case BLE_GATT_REGISTER_OP_CHR:
      MODLOG_DFLT(DEBUG,
                  "registering characteristic %s with "
                  "def_handle=%d val_handle=%d\n",
                  ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                  ctxt->chr.def_handle, ctxt->chr.val_handle);
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

void gatt_svr_print_svcs(void) { ble_gatts_show_local(); }

int gatt_svr_init(void) {
  int rc;

  /* Device name and appearance */
  //   ble_svc_gap_init();

  /* Device info */
  //   ble_svc_dis_init();
  // TODO: add these values from configuration options: serial, manufacturer,
  // etc

  /* Battery info */
  //   ble_svc_bas_init();

  rc = ble_svc_bas_battery_level_set(42);
  if (rc != 0) {
    return rc;
  }

  // rc = ble_svc_dis_serial_number_set("753E69C8D4541794");
  // if (rc != 0) {
  //   return rc;
  // }

  // rc = ble_svc_dis_manufacturer_name_set("Logitech");
  // if (rc != 0) {
  //   return rc;
  // }

  // rc = ble_svc_dis_model_number_set("MX Master 3");
  // if (rc != 0) {
  //   return rc;
  // }

  /* HID Profile */
  rc = ble_gatts_count_cfg(gatt_svr_svcs);
  if (rc != 0) {
    return rc;
  }

  rc = ble_gatts_add_svcs(gatt_svr_svcs);
  if (rc != 0) {
    return rc;
  }

  //   rc = ble_gatts_count_cfg(gatt_svr_inc_svcs);
  //   if (rc != 0) {
  //     return rc;
  //   }

  //   rc = ble_gatts_add_svcs(gatt_svr_inc_svcs);
  //   if (rc != 0) {
  //     return rc;
  //   }

  return 0;
}
