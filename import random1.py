import random
import hashlib
import telebot
from telebot import types
import base64
import os
import struct
import html

# Устанавливаем parse_mode='HTML' для всего бота
bot = telebot.TeleBot('8509694502:AAH3GktmDpccQ405s-u8BgCsHtNTa-po9HU', parse_mode='HTML')

# Словарь для хранения ключей пользователей
user_keys = {}
# Состояния для обработки диалогов
user_states = {}
# Временное хранение расшифрованных данных для запроса расширения
temp_decrypted_data = {}

# Создаем главное меню
menu = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
NewToken = types.KeyboardButton("Новый ключ")
MyToken = types.KeyboardButton("Ключ сейчас")
Encrypt = types.KeyboardButton("Зашифроваться")
Decrypt = types.KeyboardButton("Дешифровать")
EncryptFile = types.KeyboardButton("Зашифровать файл")
DecryptFile = types.KeyboardButton("Дешифровать файл")
menu.add(NewToken, MyToken, Encrypt, Decrypt, EncryptFile, DecryptFile)

back = types.ReplyKeyboardMarkup(resize_keyboard=True)
back_button = types.KeyboardButton("Назад")
back.add(back_button)

def generate_key():
    """Генерация нового ключа"""
    r = str(random.randrange(10000, 20000))
    h = hashlib.sha256(r.encode('utf-8'))
    return h.hexdigest()

def xor_encrypt(text, key):
    """Шифрование текста XOR (строки)"""
    result = ""
    for i in range(len(text)):
        key_char = key[i % len(key)]
        result += chr(ord(text[i]) ^ ord(key_char))
    return result

def xor_decrypt(encrypted_text, key):
    """Дешифрование текста XOR (строки)"""
    return xor_encrypt(encrypted_text, key)

def xor_encrypt_bytes(data, key):
    """Шифрование/дешифрование байтов XOR"""
    key_bytes = key.encode('utf-8')
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

def get_file_extension(message):
    """Определяем расширение файла из сообщения"""
    if message.voice:
        return ".ogg"
    elif message.photo:
        return ".jpg"
    elif message.document and message.document.file_name:
        name = message.document.file_name
        if '.' in name:
            return '.' + name.split('.')[-1]
        else:
            return ".bin"
    elif message.audio:
        if message.audio.file_name and '.' in message.audio.file_name:
            return '.' + message.audio.file_name.split('.')[-1]
        else:
            return ".mp3"
    elif message.video:
        return ".mp4"
    else:
        return ".bin"

def return_to_menu(chat_id, message):
    """Очистка состояний и возврат в меню"""
    keys_to_delete = [k for k in user_states if k == chat_id or str(k).startswith(f"{chat_id}_")]
    for k in keys_to_delete:
        del user_states[k]
    if chat_id in temp_decrypted_data:
        del temp_decrypted_data[chat_id]
    bot.send_message(chat_id, message, reply_markup=menu)

@bot.message_handler(commands=['start'])
def start_message(message):
    return_to_menu(message.chat.id, "Привет! Выберите действие:")

@bot.message_handler(content_types=['text'])
def text_messages(message):
    chat_id = message.chat.id
    
    if message.text == "Назад":
        return_to_menu(chat_id, "Возвращаемся в меню")
        return
    
    if chat_id in user_states:
        state = user_states[chat_id]
        
        # Шифрование текста
        if state == "waiting_for_encrypt_text":
            text_to_encrypt = message.text
            if chat_id not in user_keys:
                return_to_menu(chat_id, "❌ У вас нет ключа! Сначала создайте ключ.")
                return
            key = user_keys[chat_id]
            encrypted = xor_encrypt(text_to_encrypt, key)
            encrypted_hex = encrypted.encode('utf-8').hex()
            # Используем HTML-теги для выделения ключа и зашифрованного сообщения
            response = (
                "✅ Сообщение зашифровано!\n\n"
                "🔒 Зашифрованное сообщение (hex):\n"
                f"<pre>{encrypted_hex}</pre>\n\n"
                "🔑 Ваш ключ для дешифрования:\n"
                f"<code>{key}</code>\n\n"
                "⚠️ Отправьте эти данные другому пользователю для дешифрования."
            )
            return_to_menu(chat_id, response)
            return
        
        # Дешифрование текста: ввод ключа
        elif state == "waiting_for_decrypt_key":
            user_states[chat_id] = "waiting_for_decrypt_text"
            user_states[f"{chat_id}_key"] = message.text
            bot.send_message(chat_id, "Теперь введите зашифрованное сообщение (в hex формате):", reply_markup=back)
            return
        
        # Дешифрование текста: ввод зашифрованного текста
        elif state == "waiting_for_decrypt_text":
            encrypted_hex = message.text
            key = user_states.get(f"{chat_id}_key")
            try:
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                encrypted_text = encrypted_bytes.decode('utf-8')
                decrypted = xor_decrypt(encrypted_text, key)
                # Экранируем возможные HTML-символы в расшифрованном тексте
                safe_decrypted = html.escape(decrypted)
                response = f"✅ Сообщение расшифровано!\n\n📝 Расшифрованное сообщение:\n<code>{safe_decrypted}</code>"
                return_to_menu(chat_id, response)
            except Exception as e:
                error_msg = html.escape(str(e))
                return_to_menu(chat_id, f"❌ Ошибка при дешифровании! Убедитесь, что:\n1. Ключ правильный\n2. Зашифрованное сообщение в правильном hex формате\n\nОшибка: {error_msg}")
            return
        
        # Дешифрование файла: ввод ключа
        elif state == "waiting_for_decrypt_file_key":
            user_states[chat_id] = "waiting_for_decrypt_file_data"
            user_states[f"{chat_id}_tmp_key"] = message.text
            bot.send_message(chat_id, "Теперь отправьте файл с зашифрованными данными (в формате .txt с base64):", reply_markup=back)
            return
        
        # Дешифрование файла: ввод расширения вручную
        elif state == "waiting_for_file_extension":
            extension = message.text.strip()
            if not extension.startswith('.'):
                extension = '.' + extension
            if chat_id in temp_decrypted_data:
                decrypted_bytes = temp_decrypted_data[chat_id]
                from io import BytesIO
                bio = BytesIO(decrypted_bytes)
                bio.name = f"decrypted_file{extension}"
                bot.send_document(chat_id, bio, caption="✅ Файл расшифрован с указанным расширением.")
                del temp_decrypted_data[chat_id]
                return_to_menu(chat_id, "Готово!")
            else:
                return_to_menu(chat_id, "❌ Ошибка: данные не найдены. Начните заново.")
            return
    
    # Обработка команд меню
    if message.text == "Новый ключ":
        key = generate_key()
        user_keys[chat_id] = key
        return_to_menu(chat_id, f"✅ Создан новый ключ:\n<code>{key}</code>")
        
    elif message.text == "Ключ сейчас":
        if chat_id in user_keys:
            return_to_menu(chat_id, f"🔑 Ваш текущий ключ:\n<code>{user_keys[chat_id]}</code>\n\n⚠️ Этот ключ используется для шифрования ваших сообщений и файлов.")
        else:
            key = generate_key()
            user_keys[chat_id] = key
            return_to_menu(chat_id, f"🔑 Ключ не был найден. Создан новый ключ:\n<code>{key}</code>")
    
    elif message.text == "Зашифроваться":
        if chat_id not in user_keys:
            return_to_menu(chat_id, "❌ У вас нет ключа! Сначала создайте ключ.")
            return
        user_states[chat_id] = "waiting_for_encrypt_text"
        bot.send_message(chat_id, "Введите сообщение для шифрования:", reply_markup=back)
    
    elif message.text == "Дешифровать":
        user_states[chat_id] = "waiting_for_decrypt_key"
        bot.send_message(chat_id, "Введите ключ для дешифрования (можно использовать чужой ключ):", reply_markup=back)
    
    elif message.text == "Зашифровать файл":
        if chat_id not in user_keys:
            return_to_menu(chat_id, "❌ У вас нет ключа! Сначала создайте ключ.")
            return
        user_states[chat_id] = "waiting_for_encrypt_file"
        bot.send_message(chat_id, "Отправьте файл (голосовое сообщение, фото, документ и т.д.), который нужно зашифровать:", reply_markup=back)
    
    elif message.text == "Дешифровать файл":
        user_states[chat_id] = "waiting_for_decrypt_file_key"
        bot.send_message(chat_id, "Введите ключ для дешифрования файла:", reply_markup=back)
    
    else:
        return_to_menu(chat_id, "❌ Неизвестная команда. Выберите действие из меню.")

@bot.message_handler(content_types=['voice', 'photo', 'document', 'audio', 'video'])
def handle_files(message):
    chat_id = message.chat.id
    
    if chat_id not in user_states:
        bot.send_message(chat_id, "Сначала выберите действие в меню (например, 'Зашифровать файл').")
        return
    
    state = user_states[chat_id]
    
    if state == "waiting_for_encrypt_file":
        encrypt_file(message)
    elif state == "waiting_for_decrypt_file_data":
        decrypt_file(message)
    else:
        bot.send_message(chat_id, "Сейчас не ожидается файл. Используйте меню для выбора действия.")

def encrypt_file(message):
    chat_id = message.chat.id
    key = user_keys.get(chat_id)
    if not key:
        return_to_menu(chat_id, "❌ Ключ не найден. Создайте новый ключ.")
        return
    
    extension = get_file_extension(message)
    ext_bytes = extension.encode('utf-8')
    ext_len = len(ext_bytes)
    
    file_id = None
    if message.voice:
        file_id = message.voice.file_id
    elif message.photo:
        file_id = message.photo[-1].file_id
    elif message.document:
        file_id = message.document.file_id
    elif message.audio:
        file_id = message.audio.file_id
    elif message.video:
        file_id = message.video.file_id
    else:
        bot.send_message(chat_id, "Неподдерживаемый тип файла.")
        return
    
    try:
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        header = struct.pack('>H', ext_len) + ext_bytes
        data_with_header = header + downloaded_file
        encrypted_bytes = xor_encrypt_bytes(data_with_header, key)
        b64_data = base64.b64encode(encrypted_bytes).decode('ascii')
        
        temp_filename = f"encrypted_{chat_id}.txt"
        with open(temp_filename, "w", encoding='utf-8') as f:
            f.write(b64_data)
        
        with open(temp_filename, "rb") as f:
            caption = f"🔒 Файл зашифрован. Расширение: {extension}\n🔑 Ключ: <code>{key}</code>"
            bot.send_document(chat_id, f, caption=caption)
        
        os.remove(temp_filename)
        return_to_menu(chat_id, "✅ Файл успешно зашифрован и отправлен!")
        
    except Exception as e:
        error_msg = html.escape(str(e))
        return_to_menu(chat_id, f"❌ Ошибка при шифровании файла: {error_msg}")

def decrypt_file(message):
    chat_id = message.chat.id
    
    key = user_states.get(f"{chat_id}_tmp_key")
    if not key:
        return_to_menu(chat_id, "❌ Ключ не найден. Начните процесс заново.")
        return
    
    if not message.document:
        bot.send_message(chat_id, "Пожалуйста, отправьте файл в формате .txt с зашифрованными данными.")
        return
    
    try:
        file_id = message.document.file_id
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        try:
            b64_data = downloaded_file.decode('utf-8').strip()
        except UnicodeDecodeError:
            bot.send_message(chat_id, "Файл должен быть текстовым (.txt) с base64 данными.")
            return
        
        encrypted_bytes = base64.b64decode(b64_data)
        decrypted_with_header = xor_encrypt_bytes(encrypted_bytes, key)
        
        # Пытаемся извлечь заголовок
        if len(decrypted_with_header) >= 2:
            ext_len = struct.unpack('>H', decrypted_with_header[:2])[0]
            if ext_len > 0 and len(decrypted_with_header) >= 2 + ext_len:
                ext_bytes = decrypted_with_header[2:2+ext_len]
                try:
                    extension = ext_bytes.decode('utf-8')
                except:
                    extension = None
                if extension and extension.startswith('.'):
                    file_data = decrypted_with_header[2+ext_len:]
                    from io import BytesIO
                    bio = BytesIO(file_data)
                    bio.name = f"decrypted_file{extension}"
                    bot.send_document(chat_id, bio, caption="✅ Файл расшифрован (расширение восстановлено из метаданных).")
                    return_to_menu(chat_id, "Готово!")
                    return
        
        # Если заголовок не корректен, запрашиваем расширение
        temp_decrypted_data[chat_id] = decrypted_with_header
        user_states[chat_id] = "waiting_for_file_extension"
        bot.send_message(chat_id, "Не удалось определить расширение файла. Введите расширение (например, .jpg, .png, .ogg, .mp4):", reply_markup=back)
        
    except Exception as e:
        error_msg = html.escape(str(e))
        return_to_menu(chat_id, f"❌ Ошибка при дешифровании файла: {error_msg}")

# Запуск бота
bot.infinity_polling()
