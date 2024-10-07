#include "osquery/core/tables.h"
#include "osquery/core/windows/wmi.h"
#include "osquery/logger/logger.h"
#include "osquery/utils/conversions/tryto.h"
#include "osquery/utils/conversions/windows/strings.h"

namespace osquery {
namespace tables {

QueryData genMonitorInfo(QueryContext& context) {
  Row r;
  QueryData results;

  // Create the WMI request using WmiRequest::CreateWmiRequest
  const Expected<WmiRequest, WmiError> wmiSystemReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM WmiMonitorID",
                                   (BSTR)L"ROOT\\WMI");
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Error retreiving information from WMI.";
    return results;
  }

  const std::vector<WmiResultItem>& wmi_results = wmiSystemReq->results();

  // Iterate through WMI results and collect monitor information
  for (const auto& item : wmi_results) {
    // Collect monitor attributes such as Manufacturer, Serial Number, etc
    // these are represented as a vector of longs.
    std::vector<long> vManufacturer;
    item.GetVectorOfLongs("ManufacturerName", vManufacturer);
    std::ostringstream sManufacturer;
    for (int i : vManufacturer) {
      sManufacturer << char(i);
    };
    r["manufacturer"] = sManufacturer.str();

    std::vector<long> vProductCode;
    item.GetVectorOfLongs("ProductCodeID", vProductCode);
    std::ostringstream sProductCode;
    for (int i : vProductCode) {
      sProductCode << char(i);
    };
    r["model"] = sProductCode.str();
    std::vector<long> vSerial;
    item.GetVectorOfLongs("SerialNumberID", vSerial);
    std::ostringstream sSerial;
    for (int i : vSerial) {
      sSerial << char(i);
    };
    r["serial_number"] = sSerial.str();

    std::vector<long> vUFName;
    item.GetVectorOfLongs("UserFriendlyName", vUFName);
    std::ostringstream sUFName;
    for (int i : vUFName) {
      sUFName << char(i);
    };
    r["monitor_name"] = sUFName.str();

    // Get the instance name string
    item.GetString("InstanceName", r["instance_name"]);

    // Use GetBool to retrieve the boolean status of 'active'
    auto isActive = false;
    item.GetBool("Active", isActive);
    r["active"] = isActive ? "true" : "false";

    // Manufacture year (long) and week (uchar)
    long yrManu = 0;
    item.GetLong("YearOfManufacture", yrManu);
    uint8_t wkManu;
    item.GetUChar("WeekOfManufacture", wkManu);
    r["manufacture_year"] = INTEGER(yrManu);
    r["manufacture_week"] = INTEGER(wkManu);

    // Add this row to the results
    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery