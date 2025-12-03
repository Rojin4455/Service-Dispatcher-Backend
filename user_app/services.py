from decouple import config
import requests
import logging

logger = logging.getLogger(__name__)

GHL_TOKEN = config('GHL_TOKEN')
GHL_LOCATION_ID = config('GHL_LOCATION_ID', default='')
GHL_BASE_URL = 'https://services.leadconnectorhq.com'
GHL_API_VERSION = '2021-07-28'
GHL_OTP_CUSTOM_FIELD_ID = config('GHL_OTP_CUSTOM_FIELD_ID', default='FglwXnDBS2ANxj6SgUF5')

# GHL Custom Field IDs
GHL_CUSTOM_FIELD_AREA_OF_SERVICES = config('GHL_CUSTOM_FIELD_AREA_OF_SERVICES', default='g3Ukk2tUr9Rd9AvKywQw')
GHL_CUSTOM_FIELD_INDUSTRY_OF_SERVICES = config('GHL_CUSTOM_FIELD_INDUSTRY_OF_SERVICES', default='68SECPOi7wfRuZwC2ehl')
GHL_CUSTOM_FIELD_SERVICE_PINCODES = config('GHL_CUSTOM_FIELD_SERVICE_PINCODES', default='o7EfveTlaF0h291qIe8E')
GHL_CUSTOM_FIELD_WALLET_BALANCE = config('GHL_CUSTOM_FIELD_WALLET_BALANCE', default='zndCyATTJK0oXfwxyWUI')


def search_ghl_contact_by_email(email, location_id=None):
    """
    Search for a contact in GHL by email
    
    Args:
        email: Email address to search for
        location_id: GHL location ID (optional, uses config if not provided)
    
    Returns:
        dict: Contact data if found, None otherwise
    """
    if not location_id:
        location_id = GHL_LOCATION_ID
    
    if not location_id:
        logger.error("GHL_LOCATION_ID not configured")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/"
        headers = {
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        params = {
            'locationId': location_id,
            'query': email
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        contacts = data.get('contacts', [])
        
        # Find exact email match
        for contact in contacts:
            if contact.get('email', '').lower() == email.lower():
                return contact
        
        return contacts[0] if contacts else None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error searching GHL contact by email: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error searching GHL contact: {str(e)}")
        return None


def search_ghl_contact_by_phone(phone, location_id=None):
    """
    Search for a contact in GHL by phone number
    
    Args:
        phone: Phone number to search for
        location_id: GHL location ID (optional, uses config if not provided)
    
    Returns:
        dict: Contact data if found, None otherwise
    """
    if not location_id:
        location_id = GHL_LOCATION_ID
    
    if not location_id:
        logger.error("GHL_LOCATION_ID not configured")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/"
        headers = {
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        params = {
            'locationId': location_id,
            'query': phone
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        contacts = data.get('contacts', [])
        
        # Find exact phone match (normalize phone numbers for comparison)
        normalized_phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        for contact in contacts:
            contact_phone = contact.get('phone', '')
            normalized_contact_phone = contact_phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
            if normalized_contact_phone == normalized_phone:
                return contact
        
        return contacts[0] if contacts else None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error searching GHL contact by phone: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error searching GHL contact: {str(e)}")
        return None


def search_ghl_contact(email=None, phone=None, location_id=None):
    """
    Search for a contact in GHL by email or phone
    
    Args:
        email: Email address to search for (optional)
        phone: Phone number to search for (optional)
        location_id: GHL location ID (optional, uses config if not provided)
    
    Returns:
        dict: Contact data if found, None otherwise
    """
    # Try email first if provided
    if email:
        contact = search_ghl_contact_by_email(email, location_id)
        if contact:
            return contact
    
    # Try phone if provided and email didn't find anything
    if phone:
        contact = search_ghl_contact_by_phone(phone, location_id)
        if contact:
            return contact
    
    return None


def create_ghl_contact(contact_data, location_id=None):
    """
    Create a new contact in GHL using upsert API
    
    Args:
        contact_data: Dictionary containing contact information (should NOT include 'id')
        location_id: GHL location ID (optional, uses config if not provided)
    
    Returns:
        dict: Created contact data, None if error
    """
    if not location_id:
        location_id = GHL_LOCATION_ID
    
    if not location_id:
        logger.error("GHL_LOCATION_ID not configured")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/upsert"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        
        # Remove 'id' field if present (upsert doesn't accept it for new contacts)
        contact_data_clean = {k: v for k, v in contact_data.items() if k != 'id'}
        
        # Ensure locationId is in contact_data
        contact_data_clean['locationId'] = location_id
        
        # Set createNewIfDuplicateAllowed to False by default if not specified
        if 'createNewIfDuplicateAllowed' not in contact_data_clean:
            contact_data_clean['createNewIfDuplicateAllowed'] = False
        
        response = requests.post(url, headers=headers, json=contact_data_clean, timeout=10)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating GHL contact: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                logger.error(f"GHL API error details: {error_detail}")
            except:
                logger.error(f"GHL API error response: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error creating GHL contact: {str(e)}")
        return None


def update_ghl_contact(ghl_contact_id, contact_data):
    """
    Update an existing contact in GHL using PUT API
    
    Args:
        ghl_contact_id: GHL contact ID
        contact_data: Dictionary containing contact information to update (should NOT include 'id')
    
    Returns:
        dict: Updated contact data, None if error
    """
    if not ghl_contact_id:
        logger.error("GHL contact ID not provided for update")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/{ghl_contact_id}"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        
        # Remove 'id' field if present (update API doesn't accept it in payload)
        contact_data_clean = {k: v for k, v in contact_data.items() if k != 'id'}
        
        response = requests.put(url, headers=headers, json=contact_data_clean, timeout=10)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating GHL contact: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                logger.error(f"GHL API error details: {error_detail}")
            except:
                logger.error(f"GHL API error response: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error updating GHL contact: {str(e)}")
        return None


def sync_user_to_ghl(user_profile, location_id=None, save_contact_id=True):
    """
    Sync a user profile to GHL (search first, then update or create)
    
    Args:
        user_profile: UserProfile instance
        location_id: GHL location ID (optional, uses config if not provided)
        save_contact_id: Whether to save the contact ID to the profile (default: True)
    
    Returns:
        dict: GHL contact data if successful, None otherwise
    """
    user = user_profile.user
    
    # Determine contact ID - prioritize saved ID, then search
    contact_id = None
    if user_profile.ghl_contact_id:
        contact_id = user_profile.ghl_contact_id
    else:
        # Search for existing contact
        existing_contact = search_ghl_contact(
            email=user.email,
            phone=user_profile.phone,
            location_id=location_id
        )
        if existing_contact and existing_contact.get('id'):
            contact_id = existing_contact['id']
    
    # Prepare contact data (without 'id' field)
    contact_data = {
        'firstName': user.first_name or '',
        'lastName': user.last_name or '',
        'name': user.get_full_name() or user.username,
        'email': user.email,
        'phone': user_profile.phone,
    }
    
    # Update existing contact or create new one
    if contact_id:
        # Use update API for existing contact
        result = update_ghl_contact(contact_id, contact_data)
        if result and save_contact_id and not user_profile.ghl_contact_id:
            # Save contact ID if not already saved
            user_profile.ghl_contact_id = contact_id
            user_profile.save(update_fields=['ghl_contact_id'])
            logger.info(f"Saved GHL contact ID {contact_id} for user {user.email}")
    else:
        # Use create API for new contact
        result = create_ghl_contact(contact_data, location_id)
        
        # Extract and save contact ID from response
        if result and save_contact_id:
            # The response structure might be {'contact': {'id': '...'}} or {'id': '...'}
            contact_id_from_response = None
            if isinstance(result, dict):
                if 'contact' in result and isinstance(result['contact'], dict):
                    contact_id_from_response = result['contact'].get('id')
                elif 'id' in result:
                    contact_id_from_response = result.get('id')
            
            if contact_id_from_response:
                user_profile.ghl_contact_id = contact_id_from_response
                user_profile.save(update_fields=['ghl_contact_id'])
                logger.info(f"Saved GHL contact ID {contact_id_from_response} for user {user.email}")
    
    return result


def update_ghl_contact_custom_field(ghl_contact_id, custom_field_id, field_value):
    """
    Update a custom field in GHL contact
    
    Args:
        ghl_contact_id: GHL contact ID
        custom_field_id: Custom field ID
        field_value: Value to set for the custom field
    
    Returns:
        dict: Updated contact data if successful, None otherwise
    """
    if not ghl_contact_id:
        logger.warning("GHL contact ID not provided for custom field update")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/{ghl_contact_id}"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        
        payload = {
            'customFields': [
                {
                    'id': custom_field_id,
                    'field_value': str(field_value)
                }
            ]
        }
        
        response = requests.put(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating GHL contact custom field: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                logger.error(f"GHL API error details: {error_detail}")
            except:
                logger.error(f"GHL API error response: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error updating GHL contact custom field: {str(e)}")
        return None


def update_ghl_contact_custom_fields_bulk(ghl_contact_id, custom_fields_list):
    """
    Update multiple custom fields in GHL contact at once
    
    Args:
        ghl_contact_id: GHL contact ID
        custom_fields_list: List of dicts with 'id' and 'field_value' keys
    
    Returns:
        dict: Updated contact data if successful, None otherwise
    """
    if not ghl_contact_id:
        logger.warning("GHL contact ID not provided for custom fields update")
        return None
    
    if not custom_fields_list:
        logger.warning("No custom fields provided for update")
        return None
    
    try:
        url = f"{GHL_BASE_URL}/contacts/{ghl_contact_id}"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Version': GHL_API_VERSION,
            'Authorization': f'Bearer {GHL_TOKEN}'
        }
        
        payload = {
            'customFields': custom_fields_list
        }
        
        response = requests.put(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating GHL contact custom fields: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                logger.error(f"GHL API error details: {error_detail}")
            except:
                logger.error(f"GHL API error response: {e.response.text}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error updating GHL contact custom fields: {str(e)}")
        return None


def sync_profile_custom_fields_to_ghl(user_profile):
    """
    Sync user profile data to GHL custom fields
    
    Args:
        user_profile: UserProfile instance
    
    Returns:
        dict: Updated contact data if successful, None otherwise
    """
    if not user_profile.ghl_contact_id:
        logger.warning(f"GHL contact ID not found for user {user_profile.user.email}")
        return None
    
    custom_fields = []
    
    # Area Of Services - comma-separated service area names
    if user_profile.service_areas.exists():
        service_area_names = [area.name for area in user_profile.service_areas.all()]
        service_areas_text = ', '.join(service_area_names)
        custom_fields.append({
            'id': GHL_CUSTOM_FIELD_AREA_OF_SERVICES,
            'field_value': service_areas_text
        })
    
    # Industry Of Services - comma-separated service industry names
    if user_profile.service_industries.exists():
        service_industry_names = [industry.name for industry in user_profile.service_industries.all()]
        service_industries_text = ', '.join(service_industry_names)
        custom_fields.append({
            'id': GHL_CUSTOM_FIELD_INDUSTRY_OF_SERVICES,
            'field_value': service_industries_text
        })
    
    # Service Pincodes - comma-separated pincodes
    if user_profile.pincodes:
        pincodes_text = ', '.join(str(pincode) for pincode in user_profile.pincodes)
        custom_fields.append({
            'id': GHL_CUSTOM_FIELD_SERVICE_PINCODES,
            'field_value': pincodes_text
        })
    
    # Wallet Balance - monetary value
    custom_fields.append({
        'id': GHL_CUSTOM_FIELD_WALLET_BALANCE,
        'field_value': str(user_profile.wallet_balance)
    })
    
    if custom_fields:
        return update_ghl_contact_custom_fields_bulk(
            ghl_contact_id=user_profile.ghl_contact_id,
            custom_fields_list=custom_fields
        )
    
    return None


def send_password_reset_otp_email(email, otp_code, user_name=None, ghl_contact_id=None):
    """
    Send password reset OTP email to user and update GHL contact custom field
    
    Args:
        email: Recipient email address
        otp_code: 6-digit OTP code
        user_name: Optional user name for personalization
        ghl_contact_id: Optional GHL contact ID to update custom field
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Update GHL contact custom field with OTP if contact ID is provided
        if ghl_contact_id:
            try:
                ghl_update_result = update_ghl_contact_custom_field(
                    ghl_contact_id=ghl_contact_id,
                    custom_field_id=GHL_OTP_CUSTOM_FIELD_ID,
                    field_value=otp_code
                )
                if ghl_update_result:
                    logger.info(f"Updated GHL contact {ghl_contact_id} with OTP in custom field")
                else:
                    logger.warning(f"Failed to update GHL contact {ghl_contact_id} with OTP")
            except Exception as e:
                logger.error(f"Error updating GHL contact with OTP: {str(e)}")
                # Don't fail the entire process if GHL update fails
        
        # TODO: Implement email sending functionality
        # This is a placeholder function - implement your email service here
        # Example implementations:
        # - Django's send_mail
        # - SendGrid
        # - AWS SES
        # - SMTP
        
        # Placeholder implementation
        # Example using Django's send_mail (uncomment and configure):
        # from django.core.mail import send_mail
        # from django.conf import settings
        # 
        # subject = 'Password Reset OTP'
        # message = f'Your password reset OTP is: {otp_code}. This OTP is valid for 10 minutes.'
        # send_mail(
        #     subject,
        #     message,
        #     settings.DEFAULT_FROM_EMAIL,
        #     [email],
        #     fail_silently=False,
        # )
        
        logger.info(f"Password reset OTP email should be sent to {email} with OTP: {otp_code}")
        return True
    except Exception as e:
        logger.error(f"Error sending password reset OTP email: {str(e)}")
        return False


