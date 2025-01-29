import boto3
import logging
import os
import sys

# Enable detailed logging for debugging
boto3.set_stream_logger(name="botocore", level=logging.DEBUG)

def get_user_input(prompt, default=None):
    """
    Get user input with an optional default value.
    """
    user_input = input(f"{prompt} [{'Default: ' + default if default else 'Leave blank if not needed'}]: ").strip()
    return user_input if user_input else default

def get_user_credentials():
    """
    Prompt the user to input AWS credentials or use an existing AWS profile.
    Returns a Boto3 session.
    """
    print("\n🔹 AWS Credentials Setup")
    
    # Ask user whether to use AWS CLI profile or enter credentials manually
    use_profile = input("Do you want to use an AWS CLI profile? (yes/no): ").strip().lower()
    
    if use_profile == "yes":
        profile_name = get_user_input("Enter the AWS profile name", "default")
        
        try:
            session = boto3.Session(profile_name=profile_name)
            print(f"\n✅ Using AWS profile: {profile_name}")
        except Exception as e:
            print(f"\n❌ Error loading AWS profile: {e}")
            sys.exit(1)

    else:
        aws_access_key_id = get_user_input("Enter AWS Access Key ID")
        aws_secret_access_key = get_user_input("Enter AWS Secret Access Key")
        aws_session_token = get_user_input("Enter AWS Session Token (for MFA users)")

        # Validate that access key and secret are provided
        if not aws_access_key_id or not aws_secret_access_key:
            print("\n❌ AWS Access Key ID and Secret Access Key are required!")
            sys.exit(1)

        try:
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token if aws_session_token else None
            )
            print("\n✅ AWS Credentials entered successfully!")
        except Exception as e:
            print(f"\n❌ Error initializing AWS session: {e}")
            sys.exit(1)

    return session

def test_credentials(session):
    """
    Validate AWS credentials by calling sts.get_caller_identity().
    """
    try:
        print("\n🔍 Validating credentials with AWS STS...")
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
        
        print("\n✅ AWS Credentials are valid!")
        print(f"🔹 AWS Account ID: {identity['Account']}")
        print(f"🔹 User ARN: {identity['Arn']}")
        print(f"🔹 User ID: {identity['UserId']}")
        return True

    except Exception as e:
        print("\n❌ AWS Credentials are invalid!")
        print(f"Error: {e}")
        return False

def store_credentials(profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token):
    """
    Store the provided AWS credentials in the AWS CLI credentials file.
    """
    aws_credentials_path = os.path.expanduser("~/.aws/credentials")
    
    try:
        with open(aws_credentials_path, "a") as cred_file:
            cred_file.write(f"\n[{profile_name}]\n")
            cred_file.write(f"aws_access_key_id = {aws_access_key_id}\n")
            cred_file.write(f"aws_secret_access_key = {aws_secret_access_key}\n")
            if aws_session_token:
                cred_file.write(f"aws_session_token = {aws_session_token}\n")

        print(f"\n✅ Credentials saved under profile [{profile_name}] in {aws_credentials_path}")
    
    except Exception as e:
        print(f"\n❌ Error saving credentials: {e}")

def main():
    """
    Main execution function to handle AWS credentials input, validation, and optional storage.
    """
    session = get_user_credentials()
    
    if test_credentials(session):
        save_choice = input("\n💾 Do you want to save these credentials? (yes/no): ").strip().lower()
        
        if save_choice == "yes":
            profile_name = get_user_input("Enter a profile name for saving credentials", "custom-profile")
            aws_access_key_id = session.get_credentials().access_key
            aws_secret_access_key = session.get_credentials().secret_key
            aws_session_token = session.get_credentials().token
            
            store_credentials(profile_name, aws_access_key_id, aws_secret_access_key, aws_session_token)
        else:
            print("\n🔹 Credentials will not be saved.")

if __name__ == "__main__":
    main()
