from typing import Dict, Any
import xml.etree.ElementTree as ET
import uuid
from datetime import datetime
import base64
import hashlib
import logging
from xml.dom import minidom

logger = logging.getLogger(__name__)

class XMLService:

    def __init__(self):
        # Define namespaces
        self.namespaces = {
            '': "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
            'cac': "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
            'cbc': "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
            'ext': "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
        }
        
        # Register namespaces
        for prefix, uri in self.namespaces.items():
            ET.register_namespace(prefix, uri)

    def _extract_text(self, obj, key):
        """Extract text value from nested JSON structure"""
        if isinstance(obj, dict):
            item = obj.get(key, {})
            if isinstance(item, dict):
                return item.get('__text', '')
            return str(item)
        return ''

    def _extract_attribute(self, obj, key, attr_key):
        """Extract attribute value from nested JSON structure"""
        if isinstance(obj, dict):
            item = obj.get(key, {})
            if isinstance(item, dict):
                return item.get(f"_{attr_key}", '')
        return ''

    def _handle_document_reference(self, references, ref_id):
        """Extract document reference data"""
        if not isinstance(references, list):
            references = [references]
        
        for ref in references:
            if isinstance(ref, dict):
                ref_id_obj = ref.get('ID', {})
                if isinstance(ref_id_obj, dict) and ref_id_obj.get('__text') == ref_id:
                    return ref
        return {}

    def _extract_address(self, address_data):
        """Extract address information from nested JSON"""
        return {
            'street': self._extract_text(address_data, 'StreetName'),
            'additionalStreet': self._extract_text(address_data, 'AdditionalStreetName'),
            'building': self._extract_text(address_data, 'BuildingNumber'),
            'plot': self._extract_text(address_data, 'PlotIdentification'),
            'subdivision': self._extract_text(address_data, 'CitySubdivisionName'),
            'city': self._extract_text(address_data, 'CityName'),
            'postalCode': self._extract_text(address_data, 'PostalZone'),
            'region': self._extract_text(address_data, 'CountrySubentity'),
            'country': self._extract_text(address_data.get('Country', {}), 'IdentificationCode')
        }

    def convert_zatca_json(self, json_data):
        """Convert ZATCA JSON format to internal format"""
        invoice = json_data.get('Invoice', {})
        
        # Extract document references
        doc_refs = invoice.get('AdditionalDocumentReference', [])
        if not isinstance(doc_refs, list):
            doc_refs = [doc_refs]
        
        icv_ref = next((ref for ref in doc_refs if ref.get('ID', {}).get('__text') == 'ICV'), {})
        pih_ref = next((ref for ref in doc_refs if ref.get('ID', {}).get('__text') == 'PIH'), {})
        qr_ref = next((ref for ref in doc_refs if ref.get('ID', {}).get('__text') == 'QR'), {})
        
        # Extract PIH and QR binary data
        pih_data = pih_ref.get('Attachment', {}).get('EmbeddedDocumentBinaryObject', {}).get('__text', '')
        qr_data = qr_ref.get('Attachment', {}).get('EmbeddedDocumentBinaryObject', {}).get('__text', '')
        
        # Extract supplier data
        supplier_party = invoice.get('AccountingSupplierParty', {}).get('Party', {})
        supplier = {
            'name': supplier_party.get('PartyLegalEntity', {}).get('RegistrationName', {}).get('__text', ''),
            'vatNumber': supplier_party.get('PartyTaxScheme', {}).get('CompanyID', {}).get('__text', ''),
            'id': supplier_party.get('PartyIdentification', {}).get('ID', {}).get('__text', ''),
            'schemeID': supplier_party.get('PartyIdentification', {}).get('ID', {}).get('_schemeID', ''),
            'address': {
                'street': supplier_party.get('PostalAddress', {}).get('StreetName', {}).get('__text', ''),
                'building': supplier_party.get('PostalAddress', {}).get('BuildingNumber', {}).get('__text', ''),
                'plot': supplier_party.get('PostalAddress', {}).get('PlotIdentification', {}).get('__text', ''),
                'city': supplier_party.get('PostalAddress', {}).get('CityName', {}).get('__text', ''),
                'subdivision': supplier_party.get('PostalAddress', {}).get('CitySubdivisionName', {}).get('__text', ''),
                'postalCode': supplier_party.get('PostalAddress', {}).get('PostalZone', {}).get('__text', ''),
                'region': supplier_party.get('PostalAddress', {}).get('CountrySubentity', {}).get('__text', ''),
                'country': supplier_party.get('PostalAddress', {}).get('Country', {}).get('IdentificationCode', {}).get('__text', '')
            }
        }
        
        # Extract customer data
        customer_party = invoice.get('AccountingCustomerParty', {}).get('Party', {})
        customer = {
            'name': customer_party.get('PartyLegalEntity', {}).get('RegistrationName', {}).get('__text', ''),
            'vatNumber': customer_party.get('PartyTaxScheme', {}).get('CompanyID', {}).get('__text', ''),
            'id': customer_party.get('PartyIdentification', {}).get('ID', {}).get('__text', ''),
            'schemeID': customer_party.get('PartyIdentification', {}).get('ID', {}).get('_schemeID', ''),
            'address': {
                'street': customer_party.get('PostalAddress', {}).get('StreetName', {}).get('__text', ''),
                'additionalStreet': customer_party.get('PostalAddress', {}).get('AdditionalStreetName', {}).get('__text', ''),
                'building': customer_party.get('PostalAddress', {}).get('BuildingNumber', {}).get('__text', ''),
                'plot': customer_party.get('PostalAddress', {}).get('PlotIdentification', {}).get('__text', ''),
                'city': customer_party.get('PostalAddress', {}).get('CityName', {}).get('__text', ''),
                'subdivision': customer_party.get('PostalAddress', {}).get('CitySubdivisionName', {}).get('__text', ''),
                'postalCode': customer_party.get('PostalAddress', {}).get('PostalZone', {}).get('__text', ''),
                'region': customer_party.get('PostalAddress', {}).get('CountrySubentity', {}).get('__text', ''),
                'country': customer_party.get('PostalAddress', {}).get('Country', {}).get('IdentificationCode', {}).get('__text', '')
            }
        }
        
        # Extract tax data
        tax_totals = invoice.get('TaxTotal', [])
        if not isinstance(tax_totals, list):
            tax_totals = [tax_totals]
        tax_total = tax_totals[0] if tax_totals else {}
        tax_subtotal = tax_total.get('TaxSubtotal', {})
        
        # Extract monetary totals
        monetary_total = invoice.get('LegalMonetaryTotal', {})
        
        # Extract line items
        line_items = invoice.get('InvoiceLine', [])
        if not isinstance(line_items, list):
            line_items = [line_items]
        
        items = []
        for item in line_items:
            items.append({
                'id': item.get('ID', {}).get('__text', ''),
                'name': item.get('Item', {}).get('Name', {}).get('__text', ''),
                'quantity': item.get('InvoicedQuantity', {}).get('__text', ''),
                'unitCode': item.get('InvoicedQuantity', {}).get('_unitCode', ''),
                'price': item.get('Price', {}).get('PriceAmount', {}).get('__text', ''),
                'lineExtensionAmount': item.get('LineExtensionAmount', {}).get('__text', ''),
                'taxCategory': item.get('Item', {}).get('ClassifiedTaxCategory', {}).get('ID', {}).get('__text', ''),
                'taxPercent': item.get('Item', {}).get('ClassifiedTaxCategory', {}).get('Percent', {}).get('__text', ''),
                'taxTotal': item.get('TaxTotal', {}).get('TaxAmount', {}).get('__text', ''),
                'roundingAmount': item.get('TaxTotal', {}).get('RoundingAmount', {}).get('__text', ''),
                'allowanceCharge': {
                    'chargeIndicator': item.get('AllowanceCharge', {}).get('ChargeIndicator', {}).get('__text', ''),
                    'reason': item.get('AllowanceCharge', {}).get('AllowanceChargeReason', {}).get('__text', ''),
                    'amount': item.get('AllowanceCharge', {}).get('Amount', {}).get('__text', '')
                }
            })
        
        converted_data = {
            'profileID': invoice.get('ProfileID', {}).get('__text', ''),
            'invoiceNumber': invoice.get('ID', {}).get('__text', ''),
            'issueDate': invoice.get('IssueDate', {}).get('__text', ''),
            'issueTime': invoice.get('IssueTime', {}).get('__text', ''),
            'invoiceTypeCode': {
                'name': invoice.get('InvoiceTypeCode', {}).get('_name', ''),
                'value': invoice.get('InvoiceTypeCode', {}).get('__text', '')
            },
            'uuid': invoice.get('UUID', {}).get('__text', ''),
            'icv': icv_ref.get('UUID', {}).get('__text', '') or icv_ref.get('ID', {}).get('__text', ''),
            'pih': pih_data,
            'qr': qr_data,
            'supplier': supplier,
            'customer': customer,
            'items': items,
            'taxTotal': tax_total.get('TaxAmount', {}).get('__text', ''),
            'taxSubtotal': {
                'taxableAmount': tax_subtotal.get('TaxableAmount', {}).get('__text', ''),
                'taxAmount': tax_subtotal.get('TaxAmount', {}).get('__text', ''),
                'taxCategory': tax_subtotal.get('TaxCategory', {}).get('ID', {}).get('__text', ''),
                'taxPercent': tax_subtotal.get('TaxCategory', {}).get('Percent', {}).get('__text', '')
            },
            'totals': {
                'lineExtensionAmount': monetary_total.get('LineExtensionAmount', {}).get('__text', ''),
                'taxExclusiveAmount': monetary_total.get('TaxExclusiveAmount', {}).get('__text', ''),
                'taxInclusiveAmount': monetary_total.get('TaxInclusiveAmount', {}).get('__text', ''),
                'payableAmount': monetary_total.get('PayableAmount', {}).get('__text', '')
            },
            'delivery': {
                'actualDeliveryDate': invoice.get('Delivery', {}).get('ActualDeliveryDate', {}).get('__text', ''),
                'latestDeliveryDate': invoice.get('Delivery', {}).get('LatestDeliveryDate', {}).get('__text', '')
            },
            'paymentMeans': {
                'code': invoice.get('PaymentMeans', {}).get('PaymentMeansCode', {}).get('__text', '')
            }
        }
        
        return converted_data

    def create_element(self, parent, tag, text=None, **attrs):
        """Create XML element with proper namespace handling"""
        if ':' in tag:
            prefix, local_name = tag.split(':')
            namespace = self.namespaces[prefix]
            elem = ET.SubElement(parent, f"{{{namespace}}}{local_name}")
        else:
            namespace = self.namespaces['']
            elem = ET.SubElement(parent, f"{{{namespace}}}{tag}")
            
        if text is not None:
            elem.text = str(text)
            
        for key, value in attrs.items():
            if value is not None:
                elem.set(key, str(value))
                
        return elem
    
    def add_signature_extension(self, root: ET.Element) -> None:
        """Add UBL extensions with proper signature structure"""
        extensions = self.create_element(root, 'ext:UBLExtensions')
        extension = self.create_element(extensions, 'ext:UBLExtension')
        self.create_element(extension, 'ext:ExtensionURI', 
                          'urn:oasis:names:specification:ubl:dsig:enveloped:xades')
        content = self.create_element(extension, 'ext:ExtensionContent')
        
        # Add UBLDocumentSignatures structure
        sigs = self.create_element(content, 'sig:UBLDocumentSignatures')
        sig_info = self.create_element(sigs, 'sac:SignatureInformation')
        self.create_element(sig_info, 'cbc:ID', 'urn:oasis:names:specification:ubl:signature:1')
        self.create_element(sig_info, 'sbc:ReferencedSignatureID', 
                          'urn:oasis:names:specification:ubl:signature:Invoice')
        
        # Add detailed signature structure
        signature = self.create_element(sig_info, 'ds:Signature', Id="signature")
        
        # SignedInfo
        signed_info = self.create_element(signature, 'ds:SignedInfo')
        self.create_element(signed_info, 'ds:CanonicalizationMethod', 
                          Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        self.create_element(signed_info, 'ds:SignatureMethod', 
                          Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
        
        # Reference
        reference = self.create_element(signed_info, 'ds:Reference', Id="invoiceSignedData", URI="")
        transforms = self.create_element(reference, 'ds:Transforms')
        
        # Add required transforms
        transform1 = self.create_element(transforms, 'ds:Transform', 
                                      Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116")
        self.create_element(transform1, 'ds:XPath', 'not(//ancestor-or-self::ext:UBLExtensions)')
        
        transform2 = self.create_element(transforms, 'ds:Transform', 
                                      Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116")
        self.create_element(transform2, 'ds:XPath', 'not(//ancestor-or-self::cac:Signature)')
        
        transform3 = self.create_element(transforms, 'ds:Transform', 
                                      Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116")
        self.create_element(transform3, 'ds:XPath', 
                          'not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID=\'QR\'])')
        
        self.create_element(transforms, 'ds:Transform', 
                          Algorithm="http://www.w3.org/2006/12/xml-c14n11")
        
        self.create_element(reference, 'ds:DigestMethod', 
                          Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        self.create_element(reference, 'ds:DigestValue', 
                          '1IaleVZWDasvze2l8qjCg3hSZ1sjChTD+2XBYYfY/Dw=')
        
        # Add SignatureValue
        self.create_element(signature, 'ds:SignatureValue', 
                          'MEQCIGYxvrHutzL7ratlWFOOYCoqveEp3LcxaBPeJavGm22BAiAzazZieycwyXEg30cMA+/4Mg/RhhKXv5rdFeqe+rybFw==')
        
        # Add KeyInfo with X509Data
        key_info = self.create_element(signature, 'ds:KeyInfo')
        x509_data = self.create_element(key_info, 'ds:X509Data')
        self.create_element(x509_data, 'ds:X509Certificate', 
                          'MIICDDCCAbGgAwIBAgIGAY0wptEzMAoGCCqGSM49BAMCMBUxEzARBgNVBAMMCmVJbnZvaWNpbmcwHhcNMjQwMTIyMTAxMDUwWhcNMjkwMTIxMjEwMDAwWjBSMQswCQYDVQQGEwJTQTETMBEGA1UECwwKMzk5OTk5OTk5OTEOMAwGA1UECgwFYWdpbGUxHjAcBgNVBAMMFVRTVFpBVENBLUNvZGUtU2lnbmluZzBWMBAGByqGSM49AgEGBSuBBAAKA0IABLY+xYbQhrDv5fXd+0BRrxUgkT0TJvw7dbgKtpNL+aUOUB7cCMhtoZhJ61zqgJ1xpdbIokqz6olc7U3l9+duRFujgbIwga8wDAYDVR0TAQH/BAIwADCBngYDVR0RBIGWMIGTpIGQMIGNMT4wPAYDVQQEDDUxLVBvc05hbWV8Mi1HNHwzLWY1MjMzZDRlLTEwZDQtNGE4Yi05MjNlLTU5ZWNlNGFkNjM1NTEfMB0GCgmSJomT8ixkAQEMDzMwMDA3NTU4ODcwMDAwMzENMAsGA1UEDAwEMTEwMDEOMAwGA1UEGgwFQW1tYW4xCzAJBgNVBA8MAklUMAoGCCqGSM49BAMCA0kAMEYCIQCDFNMDCCOHcyx3scEIaS4lr0uGyizXunAIlKWHqtEt4wIhAMuN61SiTBeolBGlhK2TX4iflFTyVui2ISlKWj5HTf/D')
        
        # Add Object with XAdES properties
        ds_object = self.create_element(signature, 'ds:Object')
        qualifying_props = self.create_element(ds_object, 'xades:QualifyingProperties', 
                                            Target="signature")
        signed_props = self.create_element(qualifying_props, 'xades:SignedProperties', 
                                         Id="xadesSignedProperties")
        sig_signed_props = self.create_element(signed_props, 'xades:SignedSignatureProperties')
        
        # Add SigningTime and SigningCertificate
        self.create_element(sig_signed_props, 'xades:SigningTime', '2024-07-01T13:25:15')
        signing_cert = self.create_element(sig_signed_props, 'xades:SigningCertificate')
        cert = self.create_element(signing_cert, 'xades:Cert')
        cert_digest = self.create_element(cert, 'xades:CertDigest')
        self.create_element(cert_digest, 'ds:DigestMethod', 
                          Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        self.create_element(cert_digest, 'ds:DigestValue', 
                          'NGVkYjUzZjVlMDU4YzQ5NzA3ODUwMWQ3NzE2ODQyMTc0YTZlNjM4Y2JlNGE4MTM1MGUxZjhmMzU0OWIyMWRkNg==')
        
        issuer_serial = self.create_element(cert, 'xades:IssuerSerial')
        self.create_element(issuer_serial, 'ds:X509IssuerName', 'CN=eInvoicing')
        self.create_element(issuer_serial, 'ds:X509SerialNumber', '1705918255411')
    
    def add_document_references(self, root, invoice_data):
        """Add document references (ICV, PIH, QR)"""
        # Add ICV Reference
        icv_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(icv_ref, 'cbc:ID', 'ICV')
        self.create_element(icv_ref, 'cbc:UUID', invoice_data.get('icv', '1'))

        # Add PIH Reference
        pih_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(pih_ref, 'cbc:ID', 'PIH')
        pih_attach = self.create_element(pih_ref, 'cac:Attachment')
        pih_value = invoice_data.get('pih', '')
        if not pih_value:
            # Generate PIH if not provided
            pih_value = base64.b64encode(hashlib.sha256(str(invoice_data).encode()).hexdigest().encode()).decode()
        self.create_element(pih_attach, 'cbc:EmbeddedDocumentBinaryObject', 
                          pih_value, mimeCode="text/plain")

        # Add QR Reference
        qr_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(qr_ref, 'cbc:ID', 'QR')
        qr_attach = self.create_element(qr_ref, 'cac:Attachment')
        self.create_element(qr_attach, 'cbc:EmbeddedDocumentBinaryObject', 
                          invoice_data.get('qr', ''), mimeCode="text/plain")

    def add_signature(self, root):
        """Add signature section"""
        signature = self.create_element(root, 'cac:Signature')
        self.create_element(signature, 'cbc:ID', 
                          'urn:oasis:names:specification:ubl:signature:Invoice')
        self.create_element(signature, 'cbc:SignatureMethod', 
                          'urn:oasis:names:specification:ubl:dsig:enveloped:xades')

    def add_party_details(self, root, party_data, party_type):
        """Add party (supplier/customer) details"""
        if party_type == 'supplier':
            party_container = self.create_element(root, 'cac:AccountingSupplierParty')
        else:
            party_container = self.create_element(root, 'cac:AccountingCustomerParty')
        
        party = self.create_element(party_container, 'cac:Party')
        
        # Party Identification
        party_id = self.create_element(party, 'cac:PartyIdentification')
        self.create_element(party_id, 'cbc:ID', 
                          party_data['id'], schemeID=party_data.get('schemeID', 'CRN'))
        
        # Postal Address
        address = self.create_element(party, 'cac:PostalAddress')
        self.create_element(address, 'cbc:StreetName', party_data['address']['street'])
        if party_data['address'].get('additionalStreet'):
            self.create_element(address, 'cbc:AdditionalStreetName', 
                              party_data['address']['additionalStreet'])
        self.create_element(address, 'cbc:BuildingNumber', party_data['address']['building'])
        self.create_element(address, 'cbc:PlotIdentification', 
                          party_data['address'].get('plot', '1234'))
        self.create_element(address, 'cbc:CitySubdivisionName', 
                          party_data['address'].get('subdivision', 'NA'))
        self.create_element(address, 'cbc:CityName', party_data['address']['city'])
        self.create_element(address, 'cbc:PostalZone', party_data['address']['postalCode'])
        self.create_element(address, 'cbc:CountrySubentity', 
                          party_data['address'].get('region', 'NA'))
        country = self.create_element(address, 'cac:Country')
        self.create_element(country, 'cbc:IdentificationCode', 
                          party_data['address']['country'])
        
        # Tax Scheme
        tax_scheme = self.create_element(party, 'cac:PartyTaxScheme')
        if party_data.get('vatNumber'):
            self.create_element(tax_scheme, 'cbc:CompanyID', party_data['vatNumber'])
        scheme = self.create_element(tax_scheme, 'cac:TaxScheme')
        self.create_element(scheme, 'cbc:ID', 'VAT')
        
        # Legal Entity
        legal_entity = self.create_element(party, 'cac:PartyLegalEntity')
        self.create_element(legal_entity, 'cbc:RegistrationName', party_data['name'])

    def add_delivery_info(self, root, invoice_data):
        """Add delivery information"""
        delivery = self.create_element(root, 'cac:Delivery')
        self.create_element(delivery, 'cbc:ActualDeliveryDate', 
                          invoice_data['delivery']['actualDeliveryDate'])
        if invoice_data['delivery'].get('latestDeliveryDate'):
            self.create_element(delivery, 'cbc:LatestDeliveryDate', 
                              invoice_data['delivery']['latestDeliveryDate'])

    def add_payment_means(self, root, invoice_data):
        """Add payment means"""
        payment = self.create_element(root, 'cac:PaymentMeans')
        self.create_element(payment, 'cbc:PaymentMeansCode', 
                          invoice_data['paymentMeans'].get('code', '10'))

    def add_tax_total(self, root, invoice_data):
        """Add tax total information"""
        # First tax total with subtotal
        tax_total1 = self.create_element(root, 'cac:TaxTotal')
        self.create_element(tax_total1, 'cbc:TaxAmount', 
                          invoice_data['taxTotal'], currencyID="SAR")
        
        # Add tax subtotal
        subtotal = self.create_element(tax_total1, 'cac:TaxSubtotal')
        self.create_element(subtotal, 'cbc:TaxableAmount', 
                          invoice_data['taxSubtotal']['taxableAmount'], currencyID="SAR")
        self.create_element(subtotal, 'cbc:TaxAmount', 
                          invoice_data['taxSubtotal']['taxAmount'], currencyID="SAR")
        
        category = self.create_element(subtotal, 'cac:TaxCategory')
        self.create_element(category, 'cbc:ID', invoice_data['taxSubtotal']['taxCategory'])
        self.create_element(category, 'cbc:Percent', 
                          invoice_data['taxSubtotal']['taxPercent'])
        scheme = self.create_element(category, 'cac:TaxScheme')
        self.create_element(scheme, 'cbc:ID', 'VAT')

        # Second tax total (required by ZATCA)
        tax_total2 = self.create_element(root, 'cac:TaxTotal')
        self.create_element(tax_total2, 'cbc:TaxAmount', 
                          invoice_data['taxTotal'], currencyID="SAR")

    def add_monetary_total(self, root, invoice_data):
        """Add monetary total information"""
        total = self.create_element(root, 'cac:LegalMonetaryTotal')
        self.create_element(total, 'cbc:LineExtensionAmount', 
                          invoice_data['totals']['lineExtensionAmount'], currencyID="SAR")
        self.create_element(total, 'cbc:TaxExclusiveAmount', 
                          invoice_data['totals']['taxExclusiveAmount'], currencyID="SAR")
        self.create_element(total, 'cbc:TaxInclusiveAmount', 
                          invoice_data['totals']['taxInclusiveAmount'], currencyID="SAR")
        self.create_element(total, 'cbc:PayableAmount', 
                          invoice_data['totals']['payableAmount'], currencyID="SAR")

    def add_invoice_lines(self, root, invoice_data):
        """Add invoice line items"""
        for item in invoice_data['items']:
            line = self.create_element(root, 'cac:InvoiceLine')
            self.create_element(line, 'cbc:ID', item['id'])
            self.create_element(line, 'cbc:InvoicedQuantity', 
                              item['quantity'], unitCode=item.get('unitCode', 'PCE'))
            self.create_element(line, 'cbc:LineExtensionAmount', 
                              item['lineExtensionAmount'], currencyID="SAR")
            
            # Add AllowanceCharge
            allowance = self.create_element(line, 'cac:AllowanceCharge')
            self.create_element(allowance, 'cbc:ChargeIndicator', 
                              item['allowanceCharge'].get('chargeIndicator', 'false'))
            self.create_element(allowance, 'cbc:AllowanceChargeReason', 
                              item['allowanceCharge'].get('reason', 'discount'))
            self.create_element(allowance, 'cbc:Amount', 
                              item['allowanceCharge'].get('amount', '0.00'), currencyID="SAR")
            
            # Add Line Tax Total
            line_tax = self.create_element(line, 'cac:TaxTotal')
            self.create_element(line_tax, 'cbc:TaxAmount', 
                              item['taxTotal'], currencyID="SAR")
            self.create_element(line_tax, 'cbc:RoundingAmount', 
                              item['roundingAmount'], currencyID="SAR")
            
            # Add Item Details
            item_element = self.create_element(line, 'cac:Item')
            self.create_element(item_element, 'cbc:Name', item['name'])
            
            # Add Item Tax Category
            tax_category = self.create_element(item_element, 'cac:ClassifiedTaxCategory')
            self.create_element(tax_category, 'cbc:ID', item.get('taxCategory', 'S'))
            self.create_element(tax_category, 'cbc:Percent', item.get('taxPercent', '15.00'))
            tax_scheme = self.create_element(tax_category, 'cac:TaxScheme')
            self.create_element(tax_scheme, 'cbc:ID', 'VAT')
            
            # Add Price Information
            price = self.create_element(line, 'cac:Price')
            self.create_element(price, 'cbc:PriceAmount', 
                              item['price'], currencyID="SAR")

    def generate_ubl_xml(self, invoice_data):
        """Generate UBL 2.1 compliant XML"""
        try:
            # Create root element with default namespace
            namespace = self.namespaces['']
            root = ET.Element(f"{{{namespace}}}Invoice")
            
            # Add main elements
            self.create_element(root, 'cbc:ProfileID', 
                            invoice_data.get('profileID', 'reporting:1.0'))
            self.create_element(root, 'cbc:ID', invoice_data['invoiceNumber'])
            self.create_element(root, 'cbc:UUID', 
                            invoice_data.get('uuid', str(uuid.uuid4())))
            self.create_element(root, 'cbc:IssueDate', invoice_data['issueDate'])
            self.create_element(root, 'cbc:IssueTime', 
                            invoice_data.get('issueTime', '00:00:00'))
            self.create_element(root, 'cbc:InvoiceTypeCode', 
                            invoice_data['invoiceTypeCode']['value'],
                            name=invoice_data['invoiceTypeCode']['name'])
            self.create_element(root, 'cbc:DocumentCurrencyCode', 'SAR')
            self.create_element(root, 'cbc:TaxCurrencyCode', 'SAR')

            # Add other elements
            self._add_document_references(root, invoice_data)
            self._add_supplier_party(root, invoice_data['supplier'])
            self._add_customer_party(root, invoice_data['customer'])
            
            if 'delivery' in invoice_data:
                self._add_delivery(root, invoice_data['delivery'])
            
            if 'paymentMeans' in invoice_data:
                self._add_payment_means(root, invoice_data['paymentMeans'])
            
            self._add_tax_totals(root, invoice_data)
            self._add_monetary_total(root, invoice_data['totals'])
            self._add_invoice_lines(root, invoice_data['items'])

            # Convert to string with proper XML declaration
            xml_declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
            xml_content = ET.tostring(root, encoding='UTF-8')
            
            # Combine XML declaration with content
            final_xml = xml_declaration.encode('UTF-8') + xml_content
            
            return final_xml
            
        except Exception as e:
            logger.error(f"Error generating XML: {str(e)}")
            raise
    
    def _add_document_references(self, root, invoice_data):
        """Add document references (ICV, PIH, QR)"""
        # Add ICV Reference
        icv_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(icv_ref, 'cbc:ID', 'ICV')
        self.create_element(icv_ref, 'cbc:UUID', invoice_data.get('icv', '1'))
        
        # Add PIH Reference
        pih_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(pih_ref, 'cbc:ID', 'PIH')
        pih_attach = self.create_element(pih_ref, 'cac:Attachment')
        self.create_element(pih_attach, 'cbc:EmbeddedDocumentBinaryObject', 
                          invoice_data.get('pih', ''),
                          mimeCode='text/plain')
        
        # Add QR Reference
        qr_ref = self.create_element(root, 'cac:AdditionalDocumentReference')
        self.create_element(qr_ref, 'cbc:ID', 'QR')
        qr_attach = self.create_element(qr_ref, 'cac:Attachment')
        self.create_element(qr_attach, 'cbc:EmbeddedDocumentBinaryObject', 
                          invoice_data.get('qr', ''),
                          mimeCode='text/plain')

    # [Keep your existing helper methods (_add_supplier_party, _add_customer_party, etc.)]
    
    def _add_supplier_party(self, root, supplier_data):
        """Add supplier party information"""
        supplier_party = self.create_element(root, 'cac:AccountingSupplierParty')
        party = self.create_element(supplier_party, 'cac:Party')
        
        # Add party identification
        party_id = self.create_element(party, 'cac:PartyIdentification')
        self.create_element(party_id, 'cbc:ID', supplier_data['id'], 
                          schemeID=supplier_data.get('schemeID', 'CRN'))
        
        # Add postal address
        address = self.create_element(party, 'cac:PostalAddress')
        self._add_address_elements(address, supplier_data['address'])
        
        # Add party tax scheme
        tax_scheme = self.create_element(party, 'cac:PartyTaxScheme')
        if supplier_data.get('vatNumber'):
            self.create_element(tax_scheme, 'cbc:CompanyID', supplier_data['vatNumber'])
        scheme = self.create_element(tax_scheme, 'cac:TaxScheme')
        self.create_element(scheme, 'cbc:ID', 'VAT')
        
        # Add party legal entity
        legal_entity = self.create_element(party, 'cac:PartyLegalEntity')
        self.create_element(legal_entity, 'cbc:RegistrationName', supplier_data['name'])

    def _add_address_elements(self, address_element, address_data):
        """Add address elements to postal address"""
        self.create_element(address_element, 'cbc:StreetName', 
                          address_data['street'])
        if address_data.get('additionalStreet'):
            self.create_element(address_element, 'cbc:AdditionalStreetName', 
                              address_data['additionalStreet'])
        self.create_element(address_element, 'cbc:BuildingNumber', 
                          address_data['building'])
        self.create_element(address_element, 'cbc:PlotIdentification', 
                          address_data.get('plot', '1234'))
        self.create_element(address_element, 'cbc:CitySubdivisionName', 
                          address_data.get('subdivision', 'NA'))
        self.create_element(address_element, 'cbc:CityName', 
                          address_data['city'])
        self.create_element(address_element, 'cbc:PostalZone', 
                          address_data['postalCode'])
        self.create_element(address_element, 'cbc:CountrySubentity', 
                          address_data.get('region', 'NA'))
        country = self.create_element(address_element, 'cac:Country')
        self.create_element(country, 'cbc:IdentificationCode', 
                          address_data['country'])
        
    def _add_customer_party(self, root, customer_data):
        """Add customer party information"""
        customer_party = self.create_element(root, 'cac:AccountingCustomerParty')
        party = self.create_element(customer_party, 'cac:Party')
        
        # Add party identification
        party_id = self.create_element(party, 'cac:PartyIdentification')
        self.create_element(party_id, 'cbc:ID', customer_data['id'], 
                        schemeID=customer_data.get('schemeID', 'NAT'))
        
        # Add postal address
        address = self.create_element(party, 'cac:PostalAddress')
        self._add_address_elements(address, customer_data['address'])
        
        # Add party tax scheme
        tax_scheme = self.create_element(party, 'cac:PartyTaxScheme')
        if customer_data.get('vatNumber'):
            self.create_element(tax_scheme, 'cbc:CompanyID', customer_data['vatNumber'])
        scheme = self.create_element(tax_scheme, 'cac:TaxScheme')
        self.create_element(scheme, 'cbc:ID', 'VAT')
        
        # Add party legal entity
        legal_entity = self.create_element(party, 'cac:PartyLegalEntity')
        self.create_element(legal_entity, 'cbc:RegistrationName', customer_data['name'])

    def _add_delivery(self, root, delivery_data):
        """Add delivery information"""
        delivery = self.create_element(root, 'cac:Delivery')
        
        # Add actual delivery date
        if delivery_data.get('actualDeliveryDate'):
            self.create_element(delivery, 'cbc:ActualDeliveryDate', 
                            delivery_data['actualDeliveryDate'])
        
        # Add latest delivery date
        if delivery_data.get('latestDeliveryDate'):
            self.create_element(delivery, 'cbc:LatestDeliveryDate', 
                            delivery_data['latestDeliveryDate'])

    def _add_payment_means(self, root, payment_data):
        """Add payment means information"""
        payment_means = self.create_element(root, 'cac:PaymentMeans')
        self.create_element(payment_means, 'cbc:PaymentMeansCode', 
                        payment_data.get('code', '10'))

    def _add_tax_totals(self, root, invoice_data):
        """Add tax total information"""
        # First tax total with subtotal
        tax_total1 = self.create_element(root, 'cac:TaxTotal')
        self.create_element(tax_total1, 'cbc:TaxAmount', 
                        invoice_data['taxTotal'],
                        currencyID="SAR")
        
        # Add tax subtotal
        tax_subtotal = self.create_element(tax_total1, 'cac:TaxSubtotal')
        self.create_element(tax_subtotal, 'cbc:TaxableAmount', 
                        invoice_data['taxSubtotal']['taxableAmount'],
                        currencyID="SAR")
        self.create_element(tax_subtotal, 'cbc:TaxAmount', 
                        invoice_data['taxSubtotal']['taxAmount'],
                        currencyID="SAR")
        
        # Add tax category
        tax_category = self.create_element(tax_subtotal, 'cac:TaxCategory')
        self.create_element(tax_category, 'cbc:ID', 
                        invoice_data['taxSubtotal']['taxCategory'])
        self.create_element(tax_category, 'cbc:Percent', 
                        invoice_data['taxSubtotal']['taxPercent'])
        
        # Add tax scheme
        tax_scheme = self.create_element(tax_category, 'cac:TaxScheme')
        self.create_element(tax_scheme, 'cbc:ID', 'VAT')
        
        # Second tax total (required by ZATCA)
        tax_total2 = self.create_element(root, 'cac:TaxTotal')
        self.create_element(tax_total2, 'cbc:TaxAmount', 
                        invoice_data['taxTotal'],
                        currencyID="SAR")

    def _add_monetary_total(self, root, totals_data):
        """Add monetary total information"""
        monetary_total = self.create_element(root, 'cac:LegalMonetaryTotal')
        
        # Add amounts
        self.create_element(monetary_total, 'cbc:LineExtensionAmount', 
                        totals_data['lineExtensionAmount'],
                        currencyID="SAR")
        self.create_element(monetary_total, 'cbc:TaxExclusiveAmount', 
                        totals_data['taxExclusiveAmount'],
                        currencyID="SAR")
        self.create_element(monetary_total, 'cbc:TaxInclusiveAmount', 
                        totals_data['taxInclusiveAmount'],
                        currencyID="SAR")
        self.create_element(monetary_total, 'cbc:PayableAmount', 
                        totals_data['payableAmount'],
                        currencyID="SAR")

    def _add_invoice_lines(self, root, items):
        """Add invoice line items"""
        for item in items:
            line = self.create_element(root, 'cac:InvoiceLine')
            
            # Add line basic info
            self.create_element(line, 'cbc:ID', item['id'])
            self.create_element(line, 'cbc:InvoicedQuantity', 
                            item['quantity'],
                            unitCode=item.get('unitCode', 'PCE'))
            self.create_element(line, 'cbc:LineExtensionAmount', 
                            item['lineExtensionAmount'],
                            currencyID="SAR")
            
            # Add allowance/charge
            allowance = self.create_element(line, 'cac:AllowanceCharge')
            self.create_element(allowance, 'cbc:ChargeIndicator', 
                            item['allowanceCharge'].get('chargeIndicator', 'false'))
            self.create_element(allowance, 'cbc:AllowanceChargeReason', 
                            item['allowanceCharge'].get('reason', 'discount'))
            self.create_element(allowance, 'cbc:Amount', 
                            item['allowanceCharge'].get('amount', '0.00'),
                            currencyID="SAR")
            
            # Add line tax total
            line_tax = self.create_element(line, 'cac:TaxTotal')
            self.create_element(line_tax, 'cbc:TaxAmount', 
                            item['taxTotal'],
                            currencyID="SAR")
            self.create_element(line_tax, 'cbc:RoundingAmount', 
                            item['roundingAmount'],
                            currencyID="SAR")
            
            # Add item details
            item_detail = self.create_element(line, 'cac:Item')
            self.create_element(item_detail, 'cbc:Name', item['name'])
            
            # Add classified tax category
            tax_category = self.create_element(item_detail, 'cac:ClassifiedTaxCategory')
            self.create_element(tax_category, 'cbc:ID', 
                            item.get('taxCategory', 'S'))
            self.create_element(tax_category, 'cbc:Percent', 
                            item.get('taxPercent', '15.00'))
            tax_scheme = self.create_element(tax_category, 'cac:TaxScheme')
            self.create_element(tax_scheme, 'cbc:ID', 'VAT')
            
            # Add price information
            price = self.create_element(line, 'cac:Price')
            self.create_element(price, 'cbc:PriceAmount', 
                            item['price'],
                            currencyID="SAR")

    def create_xml_element(self, tag, text=None, **attrs):
        """Create XML element with proper namespace handling"""
        if ':' in tag:
            prefix, local_name = tag.split(':')
            uri = self.namespaces[prefix]
            elem = ET.Element(f"{{{uri}}}{local_name}")
        else:
            uri = self.namespaces['Invoice']
            elem = ET.Element(f"{{{uri}}}{tag}")

        if text is not None:
            elem.text = str(text)

        for key, value in attrs.items():
            if value is not None:
                elem.set(key, str(value))

        return elem

    def create_subelement(self, parent, tag, text=None, **attrs):
        """Create XML subelement with proper namespace handling"""
        if ':' in tag:
            prefix, local_name = tag.split(':')
            uri = self.namespaces[prefix]
            elem = ET.SubElement(parent, f"{{{uri}}}{local_name}")
        else:
            uri = self.namespaces['Invoice']
            elem = ET.SubElement(parent, f"{{{uri}}}{tag}")

        if text is not None:
            elem.text = str(text)

        for key, value in attrs.items():
            if value is not None:
                elem.set(key, str(value))

        return elem        