from flask import Flask, request, Response
import asyncio
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import threading

app = Flask(__name__)

# Add Guest TK !
GUEST_ACC = {
     "4177273001": "A9CBD59CCA19F44C6DE5B574937A5D1A62BADD7931867030C2CD36DA1156DCBE"
}

#Encrypt_ID
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

#
def encrypt_api(plain_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size)).hex()

def encrypt_api(plain_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(plain_text), AES.block_size)).hex()


async def get_jwt_async(uid, password):
    """
    Lấy JSON Web Token (JWT) từ API một cách bất đồng bộ.
    """
    token_url = f"https://jwt-steve.vercel.app/token?uid={uid}&password={password}"
    
    try:
        async with httpx.AsyncClient(verify=False) as client: # Tùy chọn: Thêm verify=False nếu bạn gặp lỗi SSL
            response = await client.get(
                token_url,
                timeout=30
            )
            
            # 1. Kiểm tra trạng thái HTTP thành công (200 OK)
            if response.status_code == 200:
                try:
                    # 2. Phân tích JSON và lấy key "token"
                    tokens_data = response.json()
                    token = tokens_data.get("token")
                    
                    if token:
                        return token
                    else:
                        print(f"Lỗi: Không tìm thấy key 'token' trong phản hồi JSON. Phản hồi đầy đủ: {tokens_data}")
                        return None
                        
                except httpx.JSONDecodeError:
                    print(f"Lỗi: Không thể phân tích phản hồi thành JSON. Phản hồi thô: {response.text[:200]}...")
                    return None
            else:
                # Trả về mã lỗi nếu status code không phải 200
                print(f"Lỗi HTTP: Yêu cầu thất bại với Status Code {response.status_code}. Phản hồi: {response.text[:200]}...")
                return None

    except httpx.ConnectTimeout:
        print("Lỗi: Kết nối bị hết thời gian (Timeout).")
        return None
    except httpx.RequestError as e:
        # Bắt các lỗi kết nối chung khác (ví dụ: SSL, DNS, ConnectError)
        print(f"Lỗi Yêu cầu (Request Error): {e}")
        return None
    except Exception as e:
        # Bắt các lỗi không mong muốn khác
        print(f"Lỗi không xác định: {e}")
        return None



# send request!
async def send_friend_request(id, token):
    url = 'https://clientbp.common.ggbluefox.com/RequestAddingFriend'
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'Authorization': f'Bearer {token}',
        'Content-Length': '16',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'clientbp.ggblueshark.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip'
    }
    encrypted_data = encrypt_api(f'08a7c4839f1e10{Encrypt_ID(id)}1801')
    data = bytes.fromhex(encrypted_data)
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            response = await client.post(url, headers=headers, data=data)
            if response.status_code == 200:
                return f"Đã gửi đến {id}"
            return f"sai lầm : {response.text}"
    except Exception as e:
        return f"thất bại: {str(e)}"

async def process_account(uid, pw, id):
    token = await get_jwt_async(uid, pw)
    if token:
        return await send_friend_request(id, token)
    return f"Không thể lấy mã thông báo cho {uid}"

async def process_all_accounts(id):
    tasks = []
    for uid, pw in GUEST_ACC.items():
        task = asyncio.create_task(process_account(uid, pw, id))
        tasks.append(task)
    return await asyncio.gather(*tasks)

def run_async(id):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    results = loop.run_until_complete(process_all_accounts(id))
    loop.close()
    print("Kết quả :", results)

@app.route('/kb')
def spam():
    id = request.args.get('uid')
    if id:
        thread = threading.Thread(target=run_async, args=(id,))
        thread.start()
        return "🚀 Bot Đã Gởi Lời Mời Kết Bạn Đến Bạn!"
    return "❗Thiếu UID !"

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
    #app.run(host='0.0.0.0', port=8398)