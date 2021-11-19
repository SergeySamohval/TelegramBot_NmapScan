import nmap
import logging

from aiogram import Bot, Dispatcher, executor, types
from os import getenv
from sys import exit
from config import users
from config import token

from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.contrib.fsm_storage.memory import MemoryStorage


#bot_token = getenv("BOT_TOKEN")
#if not bot_token:
#    exit("Error: no token provided")

bot = Bot(token)

logging.basicConfig(level=logging.INFO)

dp = Dispatcher(bot, storage=MemoryStorage())

nm = nmap.PortScanner()

class ValueIP_port(StatesGroup):
    waiting_for_IP = State()
    waiting_for_Port = State()
    waiting_for_IPSpoof = State()



@dp.message_handler(commands=['help'])
async def send_help(message: types.Message):
    if message.chat.id in users:
        await message.answer('''
        Список команд:
        /ping -- проверить доступность хоста
        /scantcp -- сканирование протокол TCP
        /scanudp -- сканирование протокол UDP
        /scanfull -- полное сканирование хоста
        /spooftcp -- сканирование с подменой IP адреса источника протокол TCP
        /spoofudp -- сканироване с подменой IP адреса источника протокол UDP
         ''')


@dp.message_handler(commands=['ping'], state='*')
async def ip_chosen_ping(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def ping_start(message: types.Message, state: FSMContext):
    ip_addr = message.text
    await state.update_data(answer1=ip_addr)
    nm.scan(hosts=ip_addr, arguments='-n -sP')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        await message.answer(host + ' is ' + status)
    await state.finish()


@dp.message_handler(commands=['scantcp'],state='*')
async def ip_chosen_scantcp(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def port_range_chosen_scantcp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IP'] = message.text
    await message.answer('Введите диапазон портов (порт.мин-порт.макс): ')
    await ValueIP_port.waiting_for_Port.set()

@dp.message_handler(state=ValueIP_port.waiting_for_Port)
async def start_scantcp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_Port'] = message.text
        port_range = data['waiting_for_Port']
        ip_addr = data['waiting_for_IP']
    nm.scan(hosts=ip_addr, ports=port_range, arguments='-sS')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                await message.answer('Порт : %s,\tсостояние : %s, \tсервис : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
        await state.finish()



@dp.message_handler(commands=['scanudp'],state='*')
async def ip_chosen_scanudp(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def port_range_chosen_scanudp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IP'] = message.text
    await ValueIP_port.next()
    await message.answer('Введите диапазон портов (порт.мин-порт.макс): ')

@dp.message_handler(state=ValueIP_port.waiting_for_Port)
async def start_scanudp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_Port'] = message.text
        port_range = data['waiting_for_Port']
        ip_addr = data['waiting_for_IP']
    nm.scan(hosts=ip_addr, ports=port_range, arguments='-sU')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                await message.answer('Порт : %s,\tсостояние : %s, \tсервис : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
        await state.finish()


@dp.message_handler(commands=['scanfull'],state='*')
async def ip_chosen_scanfull(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def start_scanfull(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IP'] = message.text
        ip_addr = data['waiting_for_IP']
    nm.scan(hosts=ip_addr, arguments='-A')
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                await message.answer('Порт : %s,\tсостояние : %s, \tсервис : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
    await state.finish()


@dp.message_handler(commands=['spooftcp'],state='*')
async def ip_chosen_spooftcp(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите сканируемый IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def ipspoof_chosen_spooftcp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IP'] = message.text
        await message.answer('Введите подменяемый IP адрес источника: ')
        await ValueIP_port.waiting_for_IPSpoof.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IPSpoof)
async def port_range_chosen_spooftcp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IPSpoof'] = message.text
    #await ValueIP_port.next()
    await message.answer('Введите диапазон портов (порт.мин-порт.макс): ')
    await ValueIP_port.waiting_for_Port.set()

@dp.message_handler(state=ValueIP_port.waiting_for_Port)
async def start_spoof(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_Port'] = message.text
        port_range = data['waiting_for_Port']
        ip_addr = data['waiting_for_IP']
        ip_spoof = data['waiting_for_IPSpoof']
    nm.scan(hosts=ip_addr, ports=port_range, arguments=f" '-D' {ip_spoof}")
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                await message.answer('Порт : %s,\tсостояние : %s, \tсервис : %s' % (port, nm[host][proto][port]['state'], nm[host][proto][port]['name']))
        await state.finish()


@dp.message_handler(commands=['spoofudp'],state='*')
async def ip_chosen_spoofudp(message: types.Message):
    if message.chat.id in users:
        await message.answer("Введите сканируемый IP адрес: ")
        await ValueIP_port.waiting_for_IP.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IP)
async def ipspoof_chosen_spoofudp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IP'] = message.text
        await message.answer('Введите подменяемый IP адрес источника: ')
        await ValueIP_port.waiting_for_IPSpoof.set()

@dp.message_handler(state=ValueIP_port.waiting_for_IPSpoof)
async def port_range_chosen_spoofudp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_IPSpoof'] = message.text
    await message.answer('Введите диапазон портов (порт.мин-порт.макс): ')
    await ValueIP_port.waiting_for_Port.set()
@dp.message_handler(state=ValueIP_port.waiting_for_Port)
async def start_spoofudp(message: types.Message, state: FSMContext):
    async with state.proxy() as data:
        data['waiting_for_Port'] = message.text
        port_range = data['waiting_for_Port']
        ip_addr = data['waiting_for_IP']
        ip_spoof = data['waiting_for_IPSpoof']
    nm.scan(hosts=ip_addr, ports=port_range, arguments=f"'-sU' '-D' {ip_spoof}")
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                await message.answer('Порт : %s,\tсостояние : %s' % (port, nm[host][proto][port]['state']))
        await state.finish()


@dp.message_handler(content_types=types.ContentTypes.TEXT)
async def do_echo_welcome(message: types.Message):
    if message.chat.id in users:
        await message.answer(text= message.from_user.first_name +', используйте команду /help')
    elif message.chat.id not in users:
        await message.answer(text=message.from_user.first_name + ', извини, но у тебя нет доступа')


if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
