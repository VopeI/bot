import random 
import hashlib
import telebot
from telebot import types

bot = telebot.TeleBot('8509694502:AAH3GktmDpccQ405s-u8BgCsHtNTa-po9HU')

# Словарь для хранения ключей пользователей
user_keys = {}
# Состояния для обработки диалогов
user_states = {}

menu = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
NewToken = types.KeyboardButton("Новый ключ")
MyToken = types.KeyboardButton("Ключ сейчас")
Encrypt = types.KeyboardButton("Зашифроваться")
Decrypt = types.KeyboardButton("Дешифровать")
menu.add(NewToken, MyToken, Encrypt, Decrypt)

back = types.ReplyKeyboardMarkup(resize_keyboard=True)
back_button = types.KeyboardButton("Назад")
back.add(back_button)

def generate_key():
    """Функция для генерации нового ключа"""
    r = str(random.randrange(10000, 20000))
    h = hashlib.sha256(r.encode('utf-8'))
    return h.hexdigest()

def xor_encrypt(text, key):
    """Шифрование XOR"""
    result = ""
    for i in range(len(text)):
        # Используем каждый символ ключа по кругу
        key_char = key[i % len(key)]
        # XOR между символами текста и ключа
        result += chr(ord(text[i]) ^ ord(key_char))
    return result

def xor_decrypt(encrypted_text, key):
    """Дешифрование XOR (такое же как шифрование)"""
    result = ""
    for i in range(len(encrypted_text)):
        key_char = key[i % len(key)]
        result += chr(ord(encrypted_text[i]) ^ ord(key_char))
    return result

def return_to_menu(chat_id, message, parse_mode=None):
    """Функция для возврата в главное меню"""
    if chat_id in user_states:
        del user_states[chat_id]
    if f"{chat_id}_key" in user_states:
        del user_states[f"{chat_id}_key"]
    if parse_mode:
        bot.send_message(chat_id, message, reply_markup=menu, parse_mode=parse_mode)
    else:
        bot.send_message(chat_id, message, reply_markup=menu)

@bot.message_handler(commands=['start'])
def start_message(message):
    return_to_menu(message.chat.id, "Привет! Выберите действие:")

@bot.message_handler(content_types=['text'])
def text_messages(message):
    chat_id = message.chat.id
    
    # Обработка кнопки "Назад"
    if message.text == "Назад":
        return_to_menu(chat_id, "Возвращаемся в меню")
        return
    
    # Проверяем состояние пользователя
    if chat_id in user_states:
        state = user_states[chat_id]
        
        if state == "waiting_for_encrypt_text":
            # Шифруем сообщение с собственным ключом
            text_to_encrypt = message.text
            key = user_keys[chat_id]
            
            # Шифруем
            encrypted = xor_encrypt(text_to_encrypt, key)
            
            # Кодируем в hex для безопасной передачи
            encrypted_hex = encrypted.encode('utf-8').hex()
            
            # Формируем сообщение с блоками кода для легкого копирования
            message_text = (
                "✅ *Сообщение зашифровано!*\n\n"
                "🔒 *Зашифрованное сообщение (hex):*\n"
                f"`\n{encrypted_hex}\n`\n\n"
                "🔑 *Ваш ключ для дешифрования:*\n"
                f"`\n{key}\n`\n\n"
                "⚠️ Отправьте эти данные другому пользователю для дешифрования.\n\n"
                "_Для копирования нажмите на текст внутри блоков кода_"
            )
            
            return_to_menu(chat_id, message_text, parse_mode='Markdown')
            return
        
        elif state == "waiting_for_decrypt_key":
            # Сохраняем ключ и запрашиваем зашифрованное сообщение
            user_states[chat_id] = "waiting_for_decrypt_text"
            user_states[f"{chat_id}_key"] = message.text  # Сохраняем временный ключ
            bot.send_message(chat_id, "Теперь введите зашифрованное сообщение (в hex формате):", reply_markup=back)
            return
        
        elif state == "waiting_for_decrypt_text":
            # Дешифруем с использованием введенного ключа
            encrypted_hex = message.text
            key = user_states.get(f"{chat_id}_key")
            
            try:
                # Декодируем из hex
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                encrypted_text = encrypted_bytes.decode('utf-8')
                
                # Дешифруем
                decrypted = xor_decrypt(encrypted_text, key)
                
                # Формируем сообщение с блоком кода для легкого копирования
                message_text = (
                    "✅ *Сообщение расшифровано!*\n\n"
                    "📝 *Расшифрованное сообщение:*\n"
                    f"`\n{decrypted}\n`\n\n"
                    "_Для копирования нажмите на текст внутри блока кода_"
                )
                
                return_to_menu(chat_id, message_text, parse_mode='Markdown')
            except Exception as e:
                return_to_menu(chat_id, f"❌ Ошибка при дешифровании! Убедитесь, что:\n1. Ключ правильный\n2. Зашифрованное сообщение в правильном hex формате\n\nОшибка: {str(e)}")
            return
    
    # Основные команды меню
    if message.text == "Новый ключ":
        key = generate_key()
        user_keys[chat_id] = key
        
        # Формируем сообщение с блоком кода для ключа
        message_text = (
            "✅ *Создан новый ключ:*\n"
            f"`\n{key}\n`\n\n"
            "_Для копирования нажмите на текст внутри блока кода_"
        )
        
        return_to_menu(chat_id, message_text, parse_mode='Markdown')
        
    elif message.text == "Ключ сейчас":
        if chat_id in user_keys:
            key = user_keys[chat_id]
            
            # Формируем сообщение с блоком кода для ключа
            message_text = (
                "🔑 *Ваш текущий ключ:*\n"
                f"`\n{key}\n`\n\n"
                "⚠️ Этот ключ используется для шифрования ваших сообщений.\n\n"
                "_Для копирования нажмите на текст внутри блока кода_"
            )
            
            return_to_menu(chat_id, message_text, parse_mode='Markdown')
        else:
            key = generate_key()
            user_keys[chat_id] = key
            
            # Формируем сообщение с блоком кода для ключа
            message_text = (
                "🔑 *Ключ не был найден. Создан новый ключ:*\n"
                f"`\n{key}\n`\n\n"
                "_Для копирования нажмите на текст внутри блока кода_"
            )
            
            return_to_menu(chat_id, message_text, parse_mode='Markdown')
    
    elif message.text == "Зашифроваться":
        if chat_id not in user_keys:
            return_to_menu(chat_id, "❌ У вас нет ключа! Сначала создайте ключ через меню 'Новый ключ' или 'Ключ сейчас'.")
            return
        
        # Запрашиваем сообщение для шифрования
        user_states[chat_id] = "waiting_for_encrypt_text"
        bot.send_message(chat_id, "Введите сообщение для шифрования:", reply_markup=back)
    
    elif message.text == "Дешифровать":
        # Запрашиваем ключ для дешифрования
        user_states[chat_id] = "waiting_for_decrypt_key"
        bot.send_message(chat_id, "Введите ключ для дешифрования (можно использовать чужой ключ):", reply_markup=back)
    
    else:
        return_to_menu(chat_id, "❌ Неизвестная команда. Выберите действие из меню.")

bot.infinity_polling()