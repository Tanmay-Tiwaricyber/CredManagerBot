import json
import os
import asyncio
import logging
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    ConversationHandler,
    CallbackQueryHandler
)

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# States for the conversation handler
MENU = 0
# Registration states
REGISTER_USERNAME, REGISTER_PASSWORD = range(1, 3)
# Login states
LOGIN_USERNAME, LOGIN_PASSWORD = range(3, 5)
# Credential states
GET_APPNAME, GET_APP_USERNAME, GET_APP_PASSWORD = range(5, 8)

# Configuration
TOKEN = "7358425810:AAHt6K9nvyovwMGgCRqlRrPHfQgmZIZbN6g"
DATA_DIR = "data"
USER_FILE = os.path.join(DATA_DIR, "users.json")
CRED_FILE = os.path.join(DATA_DIR, "credentials.json")
SALT_FILE = os.path.join(DATA_DIR, "salt.key")

class CredentialManager:
    def __init__(self):
        # Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)
        
        # Initialize encryption key and salt
        self._init_encryption()
        
        # Load data
        self.users = self._load_json(USER_FILE, {"users": {}})
        self.credentials = self._load_json(CRED_FILE, {"credentials": {}})
        logger.info(f"Initialized CredentialManager with {len(self.users['users'])} users")

    def _init_encryption(self):
        """Initialize or load encryption salt"""
        if os.path.exists(SALT_FILE):
            with open(SALT_FILE, 'rb') as f:
                self.salt = f.read()
        else:
            # Generate new salt
            self.salt = os.urandom(16)
            with open(SALT_FILE, 'wb') as f:
                f.write(self.salt)

    def _get_encryption_key(self, password: str) -> bytes:
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _load_json(self, filename: str, default: dict) -> dict:
        """Load JSON data from file"""
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
        return default

    def _save_json(self, filename: str, data: dict):
        """Save JSON data to file"""
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    def register_user(self, username: str, password: str, telegram_id: int) -> bool:
        """Register a new user"""
        if username in self.users["users"]:
            logger.warning(f"Registration failed: username '{username}' already exists")
            return False

        try:
            # Generate key and encryptor for user
            key = self._get_encryption_key(password)
            
            # Store user data
            self.users["users"][username] = {
                "key_hash": base64.b64encode(key).decode(),
                "telegram_id": telegram_id,
                "created_at": datetime.now().isoformat()
            }
            self._save_json(USER_FILE, self.users)
            
            # Initialize credentials storage for user
            self.credentials["credentials"][username] = {}
            self._save_json(CRED_FILE, self.credentials)
            
            logger.info(f"Successfully registered new user: {username}")
            return True
        except Exception as e:
            logger.error(f"Error registering user {username}: {e}")
            return False

    def verify_user(self, username: str, password: str) -> bool:
        """Verify user credentials"""
        if username not in self.users["users"]:
            logger.warning(f"Login failed: username '{username}' not found")
            return False
        
        try:
            key = self._get_encryption_key(password)
            stored_key = base64.b64decode(self.users["users"][username]["key_hash"])
            is_valid = key == stored_key
            if is_valid:
                logger.info(f"User {username} logged in successfully")
            else:
                logger.warning(f"Login failed: invalid password for user {username}")
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying user {username}: {e}")
            return False

    def save_credential(self, username: str, app_name: str, app_username: str, app_password: str):
        """Save encrypted credentials for a user"""
        if username not in self.credentials["credentials"]:
            self.credentials["credentials"][username] = {}
        
        # Get user's encryption key
        key = base64.b64decode(self.users["users"][username]["key_hash"])
        f = Fernet(key)
        
        # Encrypt credentials
        encrypted_username = f.encrypt(app_username.encode()).decode()
        encrypted_password = f.encrypt(app_password.encode()).decode()
        
        # Save encrypted credentials
        self.credentials["credentials"][username][app_name] = {
            "username": encrypted_username,
            "password": encrypted_password,
            "updated_at": datetime.now().isoformat()
        }
        self._save_json(CRED_FILE, self.credentials)

    def get_credentials(self, username: str) -> dict:
        """Get decrypted credentials for a user"""
        if username not in self.credentials["credentials"]:
            return {}
        
        # Get user's encryption key
        key = base64.b64decode(self.users["users"][username]["key_hash"])
        f = Fernet(key)
        
        # Decrypt all credentials
        result = {}
        for app_name, creds in self.credentials["credentials"][username].items():
            try:
                decrypted_username = f.decrypt(creds["username"].encode()).decode()
                decrypted_password = f.decrypt(creds["password"].encode()).decode()
                result[app_name] = {
                    "username": decrypted_username,
                    "password": decrypted_password,
                    "updated_at": creds["updated_at"]
                }
            except Exception as e:
                logger.error(f"Error decrypting credentials for {username}/{app_name}: {e}")
                continue
        
        return result

# Initialize credential manager
cred_manager = CredentialManager()

# Command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the conversation and show main menu."""
    user = update.effective_user
    keyboard = [
        [
            InlineKeyboardButton("🔐 Register", callback_data="register"),
            InlineKeyboardButton("🔑 Login", callback_data="login"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"Welcome {user.first_name} to the Secure Credential Manager! 🔒\n\n"
        "I can help you securely store and manage your credentials.\n"
        "Please choose an option:",
        reply_markup=reply_markup
    )
    return MENU

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle button presses."""
    query = update.callback_query
    await query.answer()
    
    if query.data == "register":
        await query.edit_message_text(
            "📝 Registration\n\n"
            "Please enter a username for your account:"
        )
        return REGISTER_USERNAME
    elif query.data == "login":
        await query.edit_message_text(
            "🔐 Login\n\n"
            "Please enter your username:"
        )
        return LOGIN_USERNAME
    return ConversationHandler.END

async def register_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle username input for registration."""
    username = update.message.text
    if username in cred_manager.users["users"]:
        await update.message.reply_text(
            "❌ This username is already taken.\n"
            "Please choose another username:"
        )
        return REGISTER_USERNAME
    
    context.user_data["username"] = username
    context.user_data["registering"] = True
    
    await update.message.reply_text(
        "✅ Username available!\n\n"
        "Please enter a strong password for your account.\n"
        "Make sure to remember this password as it will be used to encrypt your credentials."
    )
    return REGISTER_PASSWORD

async def register_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle password input for registration."""
    password = update.message.text
    username = context.user_data["username"]
    
    if len(password) < 8:
        await update.message.reply_text(
            "❌ Password must be at least 8 characters long.\n"
            "Please enter a stronger password:"
        )
        return REGISTER_PASSWORD
    
    # Register user
    success = cred_manager.register_user(
        username=username,
        password=password,
        telegram_id=update.effective_user.id
    )
    
    if success:
        await update.message.reply_text(
            "✅ Registration successful!\n\n"
            "You can now use the following commands:\n"
            "/save - Save new credentials\n"
            "/view - View your saved credentials\n"
            "/start - Show main menu"
        )
    else:
        await update.message.reply_text(
            "❌ Registration failed. Please try again with /start"
        )
    
    return ConversationHandler.END

async def login_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle username input for login."""
    username = update.message.text
    
    if username not in cred_manager.users["users"]:
        await update.message.reply_text(
            "❌ Username not found.\n"
            "Please try again or use /start to register:"
        )
        return LOGIN_USERNAME
    
    context.user_data["username"] = username
    context.user_data["registering"] = False
    
    await update.message.reply_text("Please enter your password:")
    return LOGIN_PASSWORD

async def login_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle password input for login."""
    password = update.message.text
    username = context.user_data["username"]
    
    if cred_manager.verify_user(username, password):
        context.user_data["logged_in"] = True
        await update.message.reply_text(
            "✅ Login successful!\n\n"
            "You can now use the following commands:\n"
            "/save - Save new credentials\n"
            "/view - View your saved credentials\n"
            "/start - Show main menu"
        )
    else:
        await update.message.reply_text(
            "❌ Invalid password.\n"
            "Please try again with /start"
        )
    
    return ConversationHandler.END

async def save_credentials_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the credential saving process."""
    if not context.user_data.get("logged_in", False):
        await update.message.reply_text(
            "❌ You must be logged in to save credentials.\n"
            "Use /start to login."
        )
        return ConversationHandler.END
    
    await update.message.reply_text(
        "💾 Save New Credentials\n\n"
        "Please enter the name of the app/website:"
    )
    return GET_APPNAME

async def save_app_name(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle app name input."""
    app_name = update.message.text
    context.user_data["app_name"] = app_name
    
    await update.message.reply_text(
        f"Saving credentials for: {app_name}\n\n"
        "Please enter the username/email:"
    )
    return GET_APP_USERNAME

async def save_app_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle app username input."""
    app_username = update.message.text
    context.user_data["app_username"] = app_username
    
    await update.message.reply_text("Please enter the password:")
    return GET_APP_PASSWORD

async def save_app_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle app password input and save credentials."""
    app_password = update.message.text
    username = context.user_data["username"]
    app_name = context.user_data["app_name"]
    app_username = context.user_data["app_username"]
    
    try:
        cred_manager.save_credential(
            username=username,
            app_name=app_name,
            app_username=app_username,
            app_password=app_password
        )
        
        await update.message.reply_text(
            f"✅ Credentials saved successfully for {app_name}!\n\n"
            "You can view them using /view"
        )
    except Exception as e:
        logger.error(f"Error saving credentials: {e}")
        await update.message.reply_text(
            "❌ Failed to save credentials.\n"
            "Please try again later."
        )
    
    return ConversationHandler.END

async def view_credentials(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show saved credentials."""
    if not context.user_data.get("logged_in", False):
        await update.message.reply_text(
            "❌ You must be logged in to view credentials.\n"
            "Use /start to login."
        )
        return
    
    username = context.user_data["username"]
    credentials = cred_manager.get_credentials(username)
    
    if not credentials:
        await update.message.reply_text(
            "You haven't saved any credentials yet.\n"
            "Use /save to add some!"
        )
        return
    
    # Format credentials nicely
    message = "🔐 Your Saved Credentials:\n\n"
    for app_name, cred in credentials.items():
        message += f"📱 {app_name}\n"
        message += f"👤 Username: {cred['username']}\n"
        message += f"🔑 Password: {cred['password']}\n"
        message += f"🕒 Updated: {cred['updated_at'].split('T')[0]}\n\n"
    
    message += "\nRemember to delete this message for security!"
    
    await update.message.reply_text(message)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the current operation."""
    await update.message.reply_text(
        "❌ Operation cancelled.\n"
        "Use /start to show the main menu."
    )
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show help message."""
    help_text = (
        "🔐 Secure Credential Manager Help\n\n"
        "Commands:\n"
        "/start - Show main menu and login/register options\n"
        "/save - Save new credentials (requires login)\n"
        "/view - View your saved credentials (requires login)\n"
        "/help - Show this help message\n"
        "/cancel - Cancel current operation\n\n"
        "Features:\n"
        "• Secure encryption of all credentials\n"
        "• Password-based key derivation\n"
        "• Safe storage of multiple accounts\n\n"
        "Security Tips:\n"
        "• Use strong, unique passwords\n"
        "• Never share your master password\n"
        "• Delete credential messages after viewing"
    )
    await update.message.reply_text(help_text)

def main() -> None:
    """Start the bot."""    # Create the Application
    app = Application.builder().token(TOKEN).build()
    
    # Create one main conversation handler for all states
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            MENU: [CallbackQueryHandler(button_handler)],
            REGISTER_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, register_username)],
            REGISTER_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, register_password)],
            LOGIN_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_username)],
            LOGIN_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_password)],
            GET_APPNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_name)],
            GET_APP_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_username)],
            GET_APP_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_password)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        name="conversation",
        persistent=False,
        per_message=False,
        per_chat=True
    )

    # Add conversation handler for saving credentials
    save_conv_handler = ConversationHandler(
        entry_points=[CommandHandler("save", save_credentials_start)],
        states={
            GET_APPNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_name)
            ],
            GET_APP_USERNAME: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_username)
            ],
            GET_APP_PASSWORD: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, save_app_password)
            ],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        name="save_credentials"
    )    # Add handlers
    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("save", save_credentials_start))
    app.add_handler(CommandHandler("view", view_credentials))

    # Start the Bot
    print("Starting bot...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nBot stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        raise
