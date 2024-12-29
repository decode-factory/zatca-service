import json
from datetime import datetime

class JSONConverter:
    @staticmethod
    def convert_to_zatca_format(input_json):
        """Convert input JSON to ZATCA format"""
        if isinstance(input_json, str):
            try:
                data = json.loads(input_json)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON string")
        else:
            data = input_json

        # Convert to ZATCA format
        zatca_data = {
            "invoiceNumber": data.get("Invoice", {}).get("cbc:ID", {}).get("__text", ""),
            "issueDate": data.get("Invoice", {}).get("cbc:IssueDate", {}).get("__text", ""),
            "issueTime": data.get("Invoice", {}).get("cbc:IssueTime", {}).get("__text", ""),
            "invoiceTypeCode": {
                "code": "388",
                "name": "0100000"
            },
            "supplier": {
                "name": data.get("Invoice", {}).get("cac:AccountingSupplierParty", {})
                    .get("cac:Party", {}).get("cac:PartyLegalEntity", {})
                    .get("cbc:RegistrationName", {}).get("__text", ""),
                "vatNumber": data.get("Invoice", {}).get("cac:AccountingSupplierParty", {})
                    .get("cac:Party", {}).get("cac:PartyTaxScheme", {})
                    .get("cbc:CompanyID", {}).get("__text", ""),
                "address": JSONConverter._extract_address(
                    data.get("Invoice", {}).get("cac:AccountingSupplierParty", {})
                    .get("cac:Party", {}).get("cac:PostalAddress", {}))
            },
            "customer": {
                "name": data.get("Invoice", {}).get("cac:AccountingCustomerParty", {})
                    .get("cac:Party", {}).get("cac:PartyLegalEntity", {})
                    .get("cbc:RegistrationName", {}).get("__text", ""),
                "vatNumber": data.get("Invoice", {}).get("cac:AccountingCustomerParty", {})
                    .get("cac:Party", {}).get("cac:PartyTaxScheme", {})
                    .get("cbc:CompanyID", {}).get("__text", ""),
                "address": JSONConverter._extract_address(
                    data.get("Invoice", {}).get("cac:AccountingCustomerParty", {})
                    .get("cac:Party", {}).get("cac:PostalAddress", {}))
            },
            "items": JSONConverter._extract_items(
                data.get("Invoice", {}).get("cac:InvoiceLine", [])),
            "totals": JSONConverter._extract_totals(
                data.get("Invoice", {}).get("cac:LegalMonetaryTotal", {})),
            "taxTotal": data.get("Invoice", {}).get("cac:TaxTotal", [{}])[0]
                .get("cbc:TaxAmount", {}).get("__text", "0.00")
        }

        return zatca_data

    @staticmethod
    def _extract_address(address_data):
        """Extract address information"""
        return {
            "street": address_data.get("cbc:StreetName", {}).get("__text", ""),
            "building": address_data.get("cbc:BuildingNumber", {}).get("__text", ""),
            "city": address_data.get("cbc:CityName", {}).get("__text", ""),
            "postalCode": address_data.get("cbc:PostalZone", {}).get("__text", ""),
            "state": address_data.get("cbc:CountrySubentity", {}).get("__text", ""),
            "country": address_data.get("cac:Country", {})
                .get("cbc:IdentificationCode", {}).get("__text", ""),
            "subdivision": address_data.get("cbc:CitySubdivisionName", {}).get("__text", "")
        }

    @staticmethod
    def _extract_items(items_data):
        """Extract line items"""
        if not isinstance(items_data, list):
            items_data = [items_data]

        items = []
        for item in items_data:
            items.append({
                "id": item.get("cbc:ID", {}).get("__text", ""),
                "name": item.get("cac:Item", {}).get("cbc:Name", {}).get("__text", ""),
                "quantity": item.get("cbc:InvoicedQuantity", {}).get("__text", "0"),
                "unitCode": item.get("cbc:InvoicedQuantity", {}).get("_unitCode", "PCE"),
                "price": item.get("cac:Price", {})
                    .get("cbc:PriceAmount", {}).get("__text", "0"),
                "lineExtensionAmount": item.get("cbc:LineExtensionAmount", {})
                    .get("__text", "0"),
                "taxCategory": item.get("cac:Item", {})
                    .get("cac:ClassifiedTaxCategory", {}).get("cbc:ID", {})
                    .get("__text", "S"),
                "taxPercent": item.get("cac:Item", {})
                    .get("cac:ClassifiedTaxCategory", {}).get("cbc:Percent", {})
                    .get("__text", "15")
            })
        return items

    @staticmethod
    def _extract_totals(totals_data):
        """Extract monetary totals"""
        return {
            "lineExtensionAmount": totals_data.get("cbc:LineExtensionAmount", {})
                .get("__text", "0"),
            "taxExclusiveAmount": totals_data.get("cbc:TaxExclusiveAmount", {})
                .get("__text", "0"),
            "taxInclusiveAmount": totals_data.get("cbc:TaxInclusiveAmount", {})
                .get("__text", "0"),
            "payableAmount": totals_data.get("cbc:PayableAmount", {})
                .get("__text", "0")
        }