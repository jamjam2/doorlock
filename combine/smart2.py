import blescan
import sys
import lcd_i2c as lcd
import RPi.GPIO as GPIO
import bluetooth._bluetooth as bluez
import math
import numpy as np
import time
import os

from time import sleep

import bluetooth._bluetooth as bluez

servo = 18
button = 19
led = 5
GPIO.setwarnings(False)
GPIO.setmode(GPIO.BCM)
GPIO.setup(servo, GPIO.OUT)
GPIO.setup(button, GPIO.IN)
GPIO.setup(led, GPIO.OUT)

servo_motor = GPIO.PWM(servo, 100)
servo_motor.start(0)

left_angle = 10
center_angle = 7.5
right_angle = 2.5


class iBeacon:
	#Init takes company ID, major, minor, and power
	#Company ID is the hex string while the rest can be the hex string or int value
	def __init__(self , companyID , areaID , unitID , power):
		self.__companyID = companyID
		if type(areaID) == int: self.__areaID = self.intToFormattedHex(areaID , 2)
		else: self.__areaID = areaID
		if type(unitID) == int: self.__unitID = self.intToFormattedHex(unitID , 2)
		else: self.__unitID = unitID
		if type(power) == int: self.__power = self.intToFormattedHex(power , 1)
		else: self.__power = power

	#Starts the iBeacon transmitting. Bluez works asyncronously
	def startBeacon(self):
		os.system('sudo hciconfig hci0 up')
		os.system('sudo hciconfig hci0 leadv')
		os.system('sudo hciconfig hci0 noscan')
		os.system('sudo hcitool -i hci0 cmd 0x08 0x0008 {0} {1} {2} {3} 00'.format(self.__companyID , self.__areaID , self.__unitID , self.__power))
		print('iBeacon up')
		print('----------------------------------------------')
	#original packet.
	def triggerEvent(self , seconds):
		self.triggerStart()
		time.sleep(seconds)
		self.triggerEnd()

	#Stop transmission of iBeacon
	def endBeacon(self):
		os.system('sudo hciconfig hci0 noleadv')
		print('iBeacon down')

	# int 60 , 2 -> string '00 3C' // int 60 , 1 -> string '3C'
	def intToFormattedHex(self , intIn , pairs):
		hexTemp = '{0:x}'.format(abs(intIn)).zfill(pairs*2).upper()
		hexOut = hexTemp[:2]
		for i in range(pairs-1): hexOut += ' ' + hexTemp[2*i+2:2*i+4]
		return hexOut

dev_id=0
#try:
sock = bluez.hci_open_dev(dev_id)
#print("ble thread started")

#except:
#print("error accessing bluetooth device...")

blescan.hci_le_set_scan_parameters(sock)
blescan.hci_enable_le_scan(sock)

#Broadcasting beacon
#GPIO.output(16, True)
cid = '1E 02 01 1A 1A FF 4C 00 02 15 E2 0A 39 F4 73 F5 4B C4 A1 2F 17 D2 AE 08 A9 61'
aid = 20  # -> '00 00'
uid = 30  # -> '00 00'
power = -59  # -> 'CA'
#Initialize iBeacon
ib = iBeacon(cid , aid , uid , power)
#Start broadcasting
ib.startBeacon()



def servo_mortor_control():
	try:
		Distance = 0
		accuracy = 0
		sample_count = 0
		while True:
			returned_list = blescan.parse_events(sock, 5)

			if len(returned_list) == 0:
				sample_count = 0
				break 
	
			for beacon in returned_list:
				if '74278bdab64445208f0c720eaf059935' in beacon:
					sample_count = sample_count + 1
					#GPIO.output(18, True)
					rssi = int(beacon.split(",")[5])
					txPower = float(beacon.split(",")[4])
					rssi_feedback = -int(beacon.split(",")[3])
					print "TxPower = ", txPower
					print beacon
					#Broadcasting beacon
					#GPIO.output(16, True)
					cid = '1E 02 01 1A 1A FF 4C 00 02 15 E2 0A 39 F4 73 F5 4B C4 A1 2F 17 D2 AE 08 A9 61'
					aid = 30  # -> '00 00'
					uid = rssi  # -> '00 00'
					power = -59  # -> 'CA'
					#Initialize iBeacon
					ib = iBeacon(cid , aid , uid , power)
					#Start broadcasting
					ib.startBeacon()


					if sample_count == 1:
						RSSI1 = rssi
						print "RSSI1 = ", RSSI1
						RSSI_FB1 = rssi_feedback
						print RSSI_FB1
					elif sample_count == 2:
						RSSI2 = rssi
						print "RSSI2 = ", RSSI2
						RSSI_FB2 = rssi
						print RSSI_FB2
					elif sample_count == 3:
						RSSI3 = rssi
						print "RSSI3 = ", RSSI3
						RSSI_FB3 = rssi
						print RSSI_FB3
					elif sample_count == 4:
						RSSI4 = rssi
						print "RSSI4 = ", RSSI4
						RSSI_FB4 = rssi
						print RSSI_FB4
					elif sample_count == 5:
						RSSI5 = rssi
						print "RSSI5 = ", RSSI5
						RSSI_FB5 = rssi
						print RSSI_FB5
					elif sample_count == 6:
						RSSI6 = rssi
						print "RSSI6 = ", RSSI6
						RSSI_FB6 = rssi
						print RSSI_FB6
					elif sample_count == 7:
						RSSI7 = rssi
						print "RSSI7 = ", RSSI7
						RSSI_FB7 = rssi
						print RSSI_FB7
					elif sample_count == 8:
						RSSI8 = rssi
						print "RSSI8 = ", RSSI8
						RSSI_FB8 = rssi
						print RSSI_FB8
					elif sample_count == 9:
						RSSI9 = rssi
						print "RSSI9 = ", RSSI9
						RSSI_FB9 = rssi
						print RSSI_FB9
					elif sample_count == 10:
						RSSI10 = rssi
						print "RSSI10 = ", RSSI10
						RSSI_FB10 = rssi
						print RSSI_FB10
					elif sample_count == 11:
						RSSI11 = rssi
						print "RSSI11 = ", RSSI11
						RSSI_FB11 = rssi
						print RSSI_FB11
					elif sample_count == 12:
						RSSI12 = rssi
						print "RSSI12 = ", RSSI12
						RSSI_FB12 = rssi
						print RSSI_FB12
					elif sample_count == 13:
						RSSI13 = rssi
						print "RSSI13 = ", RSSI13
						RSSI_FB13 = rssi
						print RSSI_FB3
					elif sample_count == 14:
						RSSI14 = rssi
						print "RSSI14 = ", RSSI14
						RSSI_FB14 = rssi
						print RSSI_FB14
					elif sample_count == 15:
						RSSI15 = rssi
						print "RSSI15 = ", RSSI15
						RSSI_FB15 = rssi
						print RSSI_FB15
					elif sample_count == 16:
						RSSI16 = rssi
						print "RSSI16 = ", RSSI16
						RSSI_FB16 = rssi
						print RSSI_FB16
					elif sample_count == 17:
						RSSI17 = rssi
						print "RSSI17 = ", RSSI17
						RSSI_FB17 = rssi
						print RSSI_FB17
					elif sample_count == 18:
						RSSI18 = rssi
						print "RSSI18 = ", RSSI18
						RSSI_FB18 = rssi
						print RSSI_FB18
					elif sample_count == 19:
						RSSI19 = rssi
						print "RSSI19 = ", RSSI19
						RSSI_FB19 = rssi
						print RSSI_FB19
					elif sample_count == 20:
						RSSI20 = rssi
						print "RSSI20 = ", RSSI20
						RSSI_FB20 = rssi
						print RSSI_FB20	


					if sample_count == 20:
						RSSI_AVG = (RSSI1 + RSSI2 + RSSI3 + RSSI4 + RSSI5 + RSSI6 + RSSI7 + RSSI8 + RSSI9 + RSSI10 + RSSI11 + RSSI12 + RSSI13 + RSSI14 + RSSI15 + RSSI16 + RSSI17 + RSSI18 + RSSI19 + RSSI20)/20.0
						RSSI_FBAVG = (RSSI_FB1 + RSSI_FB2 + RSSI_FB3 + RSSI_FB4 + RSSI_FB5 + RSSI_FB6 + RSSI_FB7 + RSSI_FB8 + RSSI_FB9 + RSSI_FB10+ RSSI_FB11 + RSSI_FB12 + RSSI_FB13 + RSSI_FB14 + RSSI_FB15 + RSSI_FB16 + RSSI_FB17 + RSSI_FB18 + RSSI_FB19 + RSSI_FB20)/20.0
						print "-----BEFORE FILTERING-----"
						print "Average = ",RSSI_AVG
						print "FB Average = ",RSSI_FBAVG
						ratio = float(RSSI_AVG)*1.0/(txPower)
						print "Ratio = ",ratio
						if(ratio < 1.0):
							Distance = math.pow(ratio, 10)
							print "distance = ", Distance
						else:
							accuracy =  (0.89976)*math.pow(ratio,7.7095) + 0.111
							print "Accuracy = ", accuracy	

						#Kalman Filter	
						print "-----AFTER FILTERING-----"
						# intial parameters
						n_iter = 40
						sz = (n_iter,) # size of array
						z = [RSSI1, RSSI_FB1, RSSI2, RSSI_FB2, RSSI3, RSSI_FB3, RSSI4, RSSI_FB4, RSSI5, RSSI_FB5, RSSI6, RSSI_FB6, RSSI7, RSSI_FB7, RSSI8, RSSI_FB8, RSSI9, RSSI_FB9, RSSI10, RSSI_FB10, RSSI11, RSSI_FB11, RSSI12, RSSI_FB12, RSSI13, RSSI_FB13, RSSI14, RSSI_FB14, RSSI15, RSSI_FB15, RSSI16, RSSI_FB16, RSSI17, RSSI_FB17, RSSI18, RSSI_FB18, RSSI19, RSSI_FB19, RSSI20, RSSI_FB20] # observations (normal about x, sigma=0.1)
						print z
						Q = 1e-5 # process variance

						# allocate space for arrays?
						xhat=np.zeros(sz)      # a posteri estimate of x
						P=np.zeros(sz)         # a posteri error estimate
						xhatminus=np.zeros(sz) # a priori estimate of x
						Pminus=np.zeros(sz)    # a priori error estimate
						K=np.zeros(sz)         # gain or blending factor

						R = 0.1**2 # estimate of measurement variance, change to see effect

						# intial guesses
						xhat[0] = -28.0
						P[0] = 5.0

						for k in range(1,n_iter):
							# time update
							xhatminus[k] = xhat[k-1]
							Pminus[k] = P[k-1]+Q

							# measurement update
							K[k] = Pminus[k]/( Pminus[k]+R )
							xhat[k] = xhatminus[k]+K[k]*(z[k]-xhatminus[k])
							P[k] = (1-K[k])*Pminus[k]
						#test_s

						xhat_AVG = 0;

						for k in range(1,n_iter):
							xhat_AVG += xhat[k]

						xhat_AVG = xhat_AVG/40.0
						print xhat_AVG

						ratio = float(xhat_AVG)*1.0/(txPower)

						print ratio
						
						Distance = 0
						accuracy = 0	

						if(ratio < 1.0):
							Distance = math.pow(ratio, 10)
							print "predicted distance :", Distance
						else:
							accuracy =  (0.89976)*math.pow(ratio,7.7095) + 0.111
							print "Accuracy = ", accuracy

						#Broadcasting beacon
						#GPIO.output(16, True)
						cid = '1E 02 01 1A 1A FF 4C 00 02 15 E2 0A 39 F4 73 F5 4B C4 A1 2F 17 D2 AE 08 A9 61'
						aid = 30  # -> '00 00'
						uid = int(RSSI_AVG)  # -> '00 00'
						power = -59  # -> 'CA'
						#Initialize iBeacon
						ib = iBeacon(cid , aid , uid , power)
						#Start broadcasting
						ib.startBeacon()
			if sample_count == 20:
				break
		time.sleep(1)
		if(GPIO.input(button)==0 and Distance <= 1.5 and accuracy <= 1.5):
			servo_motor.ChangeDutyCycle(left_angle)
			print("Button Pressed")
			print accuracy , Distance
			lcd.lcd_string("Door is open", lcd.LCD_LINE_1)
			GPIO.output(led, 1)
			sleep(5)
			servo_motor.ChangeDutyCycle(right_angle)
			print("Button Released")
			lcd.lcd_string("Door is closed", lcd.LCD_LINE_1)
			GPIO.output(led, 0)
			sleep(0.5)

	except KeyboardInterrupt:
		servo_motor.stop()
		GPIO.cleanup()

dev_id = 0
try:
	lcd.lcd_init()
	sock = bluez.hci_open_dev(dev_id)
	print "ble thread started"

except:
	print "error accessing bluetooth device..."
	sys.exit(1)

blescan.hci_le_set_scan_parameters(sock)
blescan.hci_enable_le_scan(sock)

while True:
	returned_list = blescan.parse_events(sock, 5)
	len_returnedList = len(returned_list)

	if(len_returnedList > 0):
		servo_mortor_control()

	print "----------"
	lcd.lcd_string("", lcd.LCD_LINE_1)
	sleep(0.1)

