/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

QueryData genMonitorInfo(QueryContext& context) {
  Row r;
  QueryData results;

  const auto wmiSystemReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM WmiMonitorID", stringToWstring("root/wmi"));
  if (!wmiSystemReq || wmiSystemReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve monitor information";
    return {};
  } else {
    const std::vector<WmiResultItem>& wmiResults = wmiSystemReq->results();
    for (const auto& data : wmiResults) {
      auto isActive = false;
      data.GetBool("Active", isActive);
      r["active"] = isActive ? "True" : "False";

      std::vector<long> vManufacturer;
      data.GetVectorOfLongs("ManufacturerName", vManufacturer);
      std::ostringstream sManufacturer;
      for (int i : vManufacturer) {
        sManufacturer << char(i);
      };
      r["manufacturer"] = sManufacturer.str();
      
      std::vector<long> vProductCode;
      data.GetVectorOfLongs("ProductCodeID", vProductCode);
      std::ostringstream sProductCode;
      for (int i : vProductCode) {
        sProductCode << char(i);
      };
      r["model"] = sProductCode.str();
      
      std::vector<long> vSerial;
      data.GetVectorOfLongs("SerialNumberID", vSerial);
      std::ostringstream sSerial;
      for (int i : vSerial) {
        sSerial << char(i);
      };
      r["serial"] = sSerial.str();
      
      std::vector<long> vUFName;
      data.GetVectorOfLongs("UserFriendlyName", vUFName);
      std::ostringstream sUFName;
      for (int i : vUFName) {
        sUFName << char(i);
      };
      r["monitor_name"] = sUFName.str();
      
      long manufactureWeek = 0;
      data.GetLong("WeekOfManufacture", manufactureWeek);
      r["manufacture_week"] = INTEGER(manufactureWeek);
      long manufactureYear = 0;
      data.GetLong("YearOfManufacture", manufactureYear);
      r["manufacture_year"] = INTEGER(manufactureYear);
      results.push_back(r);
    }
  }

  
  return results;
}
} // namespace tables
} // namespace osquery
