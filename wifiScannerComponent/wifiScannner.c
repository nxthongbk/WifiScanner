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

#include <time.h> /* time_t, time, ctime */

#define WIFI_SCAN_RESULT_BUFFER_SIZE 2048
char scan_result_buffer[WIFI_SCAN_RESULT_BUFFER_SIZE];
// le_mutex_Ref_t scan_result_valid;

psensor_Ref_t __psensor_ref;

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

        int remaining_size = WIFI_SCAN_RESULT_BUFFER_SIZE;
        int used = 0;
        int len = 0;
        bool need_comma = false;

        time_t rawtime;

        time(&rawtime);

        // len = snprintf(scan_result_buffer + used, remaining_size, "{\"timestamp\":\"%s\",\"WifiScanResult\":[", ctime(&rawtime));
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
                // memset(ssidBytes, 0, LE_WIFIDEFS_MAX_SSID_BYTES);
                ssidBytes[0] = 0;
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
            len = snprintf(scan_result_buffer + used, remaining_size,
                           "{\"SSID\":\"%s\",\"BSSID\":\"%s\",\"RSSI\":\"%ddBm\"}",
                           (char *)&ssidBytes[0],
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

        // le_mutex_Unlock(scan_result_valid);

        if (json_IsValid(scan_result_buffer)) {
            LE_DEBUG(scan_result_buffer);
            psensor_PushJson(__psensor_ref, 0 /* now */, scan_result_buffer);
            LE_DEBUG("Push Done");
        } else {
            LE_ERROR("Not a JSON");
        }

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

le_wifiClient_ConnectionEventHandlerRef_t WifiEventHandlerRef = NULL;

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

    // le_mutex_Lock(scan_result_valid);

    // if (json_IsValid(scan_result_buffer)) {
    //     LE_DEBUG(scan_result_buffer);
    //     psensor_PushJson(ref, 0 /* now */, scan_result_buffer);
    //     LE_DEBUG("Push Done");
    // } else {
    //     LE_ERROR("Not a JSON");
    // }
}

COMPONENT_INIT
{
    le_result_t result;

    // scan_result_valid = le_mutex_CreateNonRecursive("ScanResult");
    // le_mutex_Lock(scan_result_valid);

    LE_DEBUG("Add event indicator handler");
    WifiEventHandlerRef = le_wifiClient_AddConnectionEventHandler(WifiClientEventIndHandler, NULL);

    LE_DEBUG("Stop Wifi Client");
    le_wifiClient_Stop();
    LE_DEBUG("Start Wifi Client");
    result = le_wifiClient_Start();

    if (LE_OK == result)
    {
        LE_DEBUG("WiFi Client started.");
    }
    else if (LE_BUSY == result)
    {
        LE_DEBUG("ERROR: WiFi Client already started.");
    }
    else
    {
        LE_DEBUG("ERROR: WiFi Client not started.");
    }

    // LE_DEBUG("Start Scan");
    // if (LE_OK == le_timer_Start(scan_wifi_timer)) {
    //     LE_DEBUG("Timer wifi scan is activated");
    // } else {
    //     LE_ERROR("Failed to activate timer wifi scan");
    // }

    __psensor_ref = psensor_Create("WifiScan", DHUBIO_DATA_TYPE_JSON, "", SampleWifiScanResult, NULL);
}