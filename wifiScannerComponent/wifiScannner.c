/**
 * This module implements a test for WiFi client.
 *
 * Copyright (C) Sierra Wireless Inc.
 *
 */

#include "legato.h"
#include "interfaces.h"

#include "periodicSensor.h"
#include "json.h"

static char scan_result_buffer[DHUBIO_MAX_STRING_VALUE_LEN];

static psensor_Ref_t PSensorRef;
static le_wifiClient_ConnectionEventHandlerRef_t WifiEventHandlerRef = NULL;

static void MyHandleScanResult(
    void)
{
    le_wifiClient_AccessPointRef_t accessPointRef = 0;

    //< WiFi Scan result for available access points available
    LE_DEBUG("Scan results");
    if (NULL != (accessPointRef = le_wifiClient_GetFirstAccessPoint()))
    {
        // SSID container
        uint8_t ssidBytes[LE_WIFIDEFS_MAX_SSID_BYTES];
        // SSID length in bytes
        size_t ssidNumElements = LE_WIFIDEFS_MAX_SSID_BYTES;
        // BSSID container
        char bssidBytes[LE_WIFIDEFS_MAX_BSSID_BYTES];
        // BSSID length in bytes
        size_t bssidNumElements = LE_WIFIDEFS_MAX_BSSID_BYTES;
        // Signal Strength
        int signal_strength = 0;
        // base64 encoded
        char base64SSID[LE_BASE64_ENCODED_SIZE(LE_WIFIDEFS_MAX_SSID_BYTES) + 1];
        size_t base64SSID_len = LE_BASE64_ENCODED_SIZE(LE_WIFIDEFS_MAX_SSID_BYTES) + 1;

        int remaining_size = DHUBIO_MAX_STRING_VALUE_LEN;
        int used = 0;
        int len = 0;
        bool need_comma = false;

        len = snprintf(scan_result_buffer + used, remaining_size, "{\"WifiScanResult\":[");
        if (len < remaining_size)
        {
            used += len;
            remaining_size -= len;
        }
        else
        {
            LE_FATAL("Buffer overflow. Unable to push Wifi scan result");
        }

        do
        {
            signal_strength = le_wifiClient_GetSignalStrength(accessPointRef);
            LE_DEBUG("le_wifiClient_GetSignalStrength %d ", signal_strength);

            if (LE_OK == le_wifiClient_GetSsid(accessPointRef, &ssidBytes[0], &ssidNumElements))
            {
                LE_DEBUG("le_wifiClient_GetSsid OK, ssidLength %d;"
                         "SSID: \"%.*s\" ",
                         (int)ssidNumElements,
                         (int)ssidNumElements,
                         (char *)&ssidBytes[0]);
            }
            else
            {
                LE_ERROR("le_wifiClient_GetSsid ERROR");
                ssidBytes[0] = 0;
                ssidNumElements = 0;
            }

            if (LE_OK == le_wifiClient_GetBssid(accessPointRef, &bssidBytes[0], bssidNumElements))
            {
                LE_DEBUG("le_wifiClient_GetBssid OK, BSSID: \"%s\" ",
                         (char *)&bssidBytes[0]);
            }
            else
            {
                LE_ERROR("le_wifiClient_GetBssid ERROR");
                memset(bssidBytes, 0, LE_WIFIDEFS_MAX_BSSID_BYTES);
            }

            if (need_comma)
            {
                len = snprintf(scan_result_buffer + used, remaining_size, ",");
                if (len < remaining_size)
                {
                    used += len;
                    remaining_size -= len;
                }
                else
                {
                    LE_FATAL("Buffer overflow. Unable to push Wifi scan result");
                }
            }
            else
            {
                need_comma = true;
            }

            if (le_base64_Encode(ssidBytes,
                                 ssidNumElements,
                                 base64SSID,
                                 &base64SSID_len) != LE_OK)
            {
                LE_ERROR("Failed to encoding data!");
            }

            len = snprintf(scan_result_buffer + used, remaining_size,
                           "{\"SSID\":\"%s\",\"BSSID\":\"%s\",\"RSSI\":\"%ddBm\"}",
                           (char *)&base64SSID[0],
                           (char *)&bssidBytes[0],
                           signal_strength);
            if (len < remaining_size)
            {
                used += len;
                remaining_size -= len;
            }
            else
            {
                LE_FATAL("Buffer overflow. Unable to push Wifi scan result");
            }

        } while (NULL != (accessPointRef = le_wifiClient_GetNextAccessPoint()));

        len = snprintf(scan_result_buffer + used, remaining_size, "]}");
        if (len < remaining_size)
        {
            used += len;
            remaining_size -= len;
        }
        else
        {
            LE_FATAL("Buffer overflow. Unable to push Wifi scan result");
        }

        LE_ASSERT(json_IsValid(scan_result_buffer));

        psensor_PushJson(PSensorRef, 0 /* now */, scan_result_buffer);

        LE_DEBUG("Done");
    }
    else
    {
        LE_ERROR("le_wifiClient_GetFirstAccessPoint ERROR");
    }
}

static void WifiClientEventIndHandler(
    const le_wifiClient_EventInd_t *wifiEventPtr, ///< [IN] Wifi event
    void *contextPtr                              ///< [IN] Associated context pointer
)
{
    LE_DEBUG("WiFi client event: %d, interface: %s, bssid: %s",
             wifiEventPtr->event,
             wifiEventPtr->ifName,
             wifiEventPtr->apBssid);

    switch (wifiEventPtr->event)
    {
    case LE_WIFICLIENT_EVENT_CONNECTED:
    {
        // WiFi Client Connected
        LE_DEBUG("LE_WIFICLIENT_EVENT_CONNECTED");
    }
    break;

    case LE_WIFICLIENT_EVENT_DISCONNECTED:
    {
        // WiFi client Disconnected
        LE_DEBUG("LE_WIFICLIENT_EVENT_DISCONNECTED");
        LE_DEBUG("disconnectCause: %d", wifiEventPtr->disconnectionCause);
    }
    break;

    case LE_WIFICLIENT_EVENT_SCAN_DONE:
    {
        LE_DEBUG("LE_WIFICLIENT_EVENT_SCAN_DONE: ");
        MyHandleScanResult();
    }
    break;

    default:
        LE_ERROR("ERROR Unknown event %d", wifiEventPtr->event);
        break;
    }
}

static void SampleWifiScanResult(
    psensor_Ref_t ref, void *context)
{
    if (LE_OK == le_wifiClient_Scan())
    {
        LE_DEBUG("Wifi scan is triggered");
    }
    else
    {
        LE_ERROR("Unable to start wifi scan");
    }
}

COMPONENT_INIT
{
    le_result_t result;

    LE_DEBUG("Add event indicator handler");
    WifiEventHandlerRef = le_wifiClient_AddConnectionEventHandler(WifiClientEventIndHandler, NULL);

    LE_DEBUG("Start Wifi Client");
    result = le_wifiClient_Start();

    if (LE_OK == result)
    {
        LE_DEBUG("WiFi Client started.");
    }
    else if (LE_BUSY == result)
    {
        LE_DEBUG("WiFi Client already started.");
    }
    else
    {
        LE_FATAL("WiFi Client not started.");
    }

    PSensorRef = psensor_Create("WifiScan", DHUBIO_DATA_TYPE_JSON, "", SampleWifiScanResult, NULL);
}