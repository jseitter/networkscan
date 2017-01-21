package io.openbac.tools;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.joda.time.Instant;

import com.serotonin.bacnet4j.LocalDevice;
import com.serotonin.bacnet4j.RemoteDevice;
import com.serotonin.bacnet4j.RemoteObject;
import com.serotonin.bacnet4j.event.DeviceEventListener;
import com.serotonin.bacnet4j.exception.BACnetException;
import com.serotonin.bacnet4j.exception.PropertyValueException;
import com.serotonin.bacnet4j.npdu.ip.IpNetworkBuilder;
import com.serotonin.bacnet4j.obj.BACnetObject;
import com.serotonin.bacnet4j.service.confirmed.ReinitializeDeviceRequest.ReinitializedStateOfDevice;
import com.serotonin.bacnet4j.service.unconfirmed.WhoIsRequest;
import com.serotonin.bacnet4j.transport.DefaultTransport;
import com.serotonin.bacnet4j.type.Encodable;
import com.serotonin.bacnet4j.type.constructed.Address;
import com.serotonin.bacnet4j.type.constructed.Choice;
import com.serotonin.bacnet4j.type.constructed.DateTime;
import com.serotonin.bacnet4j.type.constructed.PropertyReference;
import com.serotonin.bacnet4j.type.constructed.PropertyValue;
import com.serotonin.bacnet4j.type.constructed.Sequence;
import com.serotonin.bacnet4j.type.constructed.SequenceOf;
import com.serotonin.bacnet4j.type.constructed.TimeStamp;
import com.serotonin.bacnet4j.type.enumerated.EventState;
import com.serotonin.bacnet4j.type.enumerated.EventType;
import com.serotonin.bacnet4j.type.enumerated.MessagePriority;
import com.serotonin.bacnet4j.type.enumerated.NotifyType;
import com.serotonin.bacnet4j.type.enumerated.ObjectType;
import com.serotonin.bacnet4j.type.enumerated.PropertyIdentifier;
import com.serotonin.bacnet4j.type.notificationParameters.NotificationParameters;
import com.serotonin.bacnet4j.type.primitive.Boolean;
import com.serotonin.bacnet4j.type.primitive.CharacterString;
import com.serotonin.bacnet4j.type.primitive.ObjectIdentifier;
import com.serotonin.bacnet4j.type.primitive.UnsignedInteger;
import com.serotonin.bacnet4j.util.DiscoveryUtils;
import com.serotonin.bacnet4j.util.PropertyReferences;
import com.serotonin.bacnet4j.util.PropertyValues;
import com.serotonin.bacnet4j.util.RequestUtils;

public class NetworkScanner implements DeviceEventListener {

	private LocalDevice localDevice;
	private HashMap<String, RemoteDevice> devices = new HashMap<String, RemoteDevice>();

	public static void main(String[] args) throws Exception {

		NetworkScanner networkScan = new NetworkScanner();
		System.out.println("sending whois broadcast");
		networkScan.sendWhoIsBroadcast();
		// networkScan.sendWhoIsUnconfirmed();
		System.out.println("waiting for reply");
		Thread.sleep(10000);

		networkScan.scanProperties();

		//Thread.sleep(10000);
		System.exit(0);

	}

	private void scanProperties() throws BACnetException, IOException {
	
		for(RemoteDevice rd : localDevice.getRemoteDevices()) {
				
			DiscoveryUtils.getExtendedDeviceInformation(localDevice, rd);
			
			Instant now = Instant.now();
			String date= ""+now.toDateTime().getYear()+now.toDateTime().getMonthOfYear()+now.toDateTime().getDayOfMonth();
			File dir = new File(date);
			dir.mkdirs();
			File csvFile = new File(dir,rd.getName()+rd.getInstanceNumber()+".csv");
			FileWriter csv = new FileWriter(csvFile);
			PrintWriter pw = new PrintWriter(csv);
			
			
			pw.println("DEVICE;"+rd.getAddress().toString()+";VENDOR:"+rd.getVendorId()+" "+rd.getVendorName()+";MODEL:"+rd.getModelName()+";INSTANCE:"+rd.getInstanceNumber()+";MAXPDU:"+rd.getMaxAPDULengthAccepted()+";PROTOVERSION:"+rd.getProtocolVersion()+";PROTOREVISION:"+rd.getProtocolRevision()+";MAXRPMULT:"+rd.getMaxReadMultipleReferences());
			System.out.println("scanning "+rd.toExtendedString());
			
			SequenceOf<ObjectIdentifier> oids = RequestUtils.getObjectList(localDevice, rd);
//            List<ObjectIdentifier> oids = ((SequenceOf<ObjectIdentifier>) localDevice.sendReadPropertyAllowNull(rd, rd
//                    .getObjectIdentifier(), PropertyIdentifier.objectList)).getValues();
            
            PropertyReferences refs = new PropertyReferences();
			for(ObjectIdentifier oid : oids) {
		           addPropertyReferences(refs, oid);
			}
			

			PropertyValues pvs = RequestUtils.readProperties(localDevice, rd, refs, null);
//            PropertyValues pvs = localDevice.readProperties(rd, refs);

            pw.println();
            for(Map.Entry<ObjectIdentifier, List<PropertyReference>> entry :refs.getProperties().entrySet()) {
            ObjectIdentifier oid = entry.getKey();

            System.out.println("------------------------------------------------------------------------");
            System.out.println("OBJECT: "+oid.toString());
            System.out.println("------------------------------------------------------------------------");
            pw.print("OBJECT;"+oid.toString()+";"+oid.getObjectType().toString()+";"+oid.getInstanceNumber()+";");
            for(PropertyReference pref: entry.getValue()) {
            	try {
					System.out.println(pref.getPropertyIdentifier().toString()+":"+pvs.get(oid, pref.getPropertyIdentifier()).toString());
					pw.print(pref.getPropertyIdentifier().toString()+":"+pvs.get(oid, pref.getPropertyIdentifier()).toString()+";");
				} catch (PropertyValueException e) {
					System.out.println("exc:"+e.getError().toString());
				}
            	}
            pw.println();
            }
    		pw.close();
    		csv.close();
		}
		
	}

	
	public NetworkScanner() throws Exception {
		// to receive broadcasts socket must be bound to the
		// wildcard address
		localDevice = new LocalDevice(999999, new DefaultTransport(new IpNetworkBuilder().build()));
		//localDevice = new LocalDevice(54321, "192.168.10.255", "0.0.0.0");

		localDevice.getEventHandler().addListener(this);

		try {
			localDevice.initialize();
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
	}

	public void sendWhoIsBroadcast() throws BACnetException {

		
		WhoIsRequest whois = new WhoIsRequest();
		localDevice.sendLocalBroadcast(whois);
	}

//	public void sendWhoIsUnconfirmed() throws BACnetException {
//		WhoIsRequest whois = new WhoIsRequest();
//		localDevice.sendUnconfirmed(
//				new InetSocketAddress("10.20.20.255", 47808), new Network(0,
//						"0"), whois);
//	}

	public void listenerException(Throwable e) {
		// TODO Auto-generated method stub
		System.out.println("exc");
		e.printStackTrace();
	}


	public void iAmReceived(RemoteDevice d) {
		// TODO Auto-generated method stub
		System.out.println("IAm von :" + d.getInstanceNumber() + " "
				+ d.getVendorId() + " " + d.getAddress().toString());
		devices.put(d.getName(), d);
//		try {
//			localDevice.getExtendedDeviceInformation(d);
//			 System.out.println(d.getName());
//		} catch (BACnetException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}


	public boolean allowPropertyWrite(BACnetObject obj, PropertyValue pv) {
		// TODO Auto-generated method stub
		return false;
	}


	public void propertyWritten(BACnetObject obj, PropertyValue pv) {
		// TODO Auto-generated method stub
		System.out.println("property written");
	}


	public void iHaveReceived(RemoteDevice d, RemoteObject o) {
		// TODO Auto-generated method stub
		System.out.println("ihaverecv");
	}


	public void covNotificationReceived(
			UnsignedInteger subscriberProcessIdentifier,
			RemoteDevice initiatingDevice,
			ObjectIdentifier monitoredObjectIdentifier,
			UnsignedInteger timeRemaining,
			SequenceOf<PropertyValue> listOfValues) {
		// TODO Auto-generated method stub
		System.out.println("covNotification");
	}


	public void eventNotificationReceived(UnsignedInteger processIdentifier,
			RemoteDevice initiatingDevice,
			ObjectIdentifier eventObjectIdentifier, TimeStamp timeStamp,
			UnsignedInteger notificationClass, UnsignedInteger priority,
			EventType eventType, CharacterString messageText,
			NotifyType notifyType, Boolean ackRequired, EventState fromState,
			EventState toState, NotificationParameters eventValues) {
		// TODO Auto-generated method stub
		System.out.println("eventNotification");
	}


	public void textMessageReceived(RemoteDevice textMessageSourceDevice,
			Choice messageClass, MessagePriority messagePriority,
			CharacterString message) {
		// TODO Auto-generated method stub
		System.out.println("textMessage");
	}


	public void privateTransferReceived(UnsignedInteger vendorId,
			UnsignedInteger serviceNumber, Encodable serviceParameters) {
		// TODO Auto-generated method stub
		System.out.println("privateTransfer");
	}


	public void reinitializeDevice(
			ReinitializedStateOfDevice reinitializedStateOfDevice) {
		// TODO Auto-generated method stub
		System.out.println("reinitDevice");
	}


	public void synchronizeTime(DateTime dateTime, boolean utc) {
		// TODO Auto-generated method stub
		System.out.println("syncTime");
	}

	private void addPropertyReferences(PropertyReferences refs,
			ObjectIdentifier oid) {
		refs.add(oid, PropertyIdentifier.objectName);
		

		ObjectType type = oid.getObjectType();
		if (ObjectType.device.equals(type)) {
			refs.add(oid, PropertyIdentifier.location);
			refs.add(oid, PropertyIdentifier.localTime);
			refs.add(oid, PropertyIdentifier.localDate);
			refs.add(oid, PropertyIdentifier.protocolRevision);
			
		}
		if (ObjectType.accumulator.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.units);
			refs.add(oid, PropertyIdentifier.presentValue);
			refs.add(oid, PropertyIdentifier.statusFlags);
			refs.add(oid, PropertyIdentifier.outOfService);
			
		} else if (ObjectType.analogInput.equals(type)
				|| ObjectType.analogOutput.equals(type)
				|| ObjectType.analogValue.equals(type)
				|| ObjectType.pulseConverter.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.units);
			refs.add(oid, PropertyIdentifier.presentValue);
			refs.add(oid, PropertyIdentifier.covIncrement);
			refs.add(oid, PropertyIdentifier.statusFlags);
			refs.add(oid, PropertyIdentifier.outOfService);
			
			
		} else if (ObjectType.binaryInput.equals(type)
				|| ObjectType.binaryOutput.equals(type)
				|| ObjectType.binaryValue.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.inactiveText);
			refs.add(oid, PropertyIdentifier.activeText);
			refs.add(oid, PropertyIdentifier.presentValue);
			refs.add(oid, PropertyIdentifier.covIncrement);
			refs.add(oid, PropertyIdentifier.statusFlags);
			refs.add(oid, PropertyIdentifier.outOfService);

		} else if (ObjectType.lifeSafetyPoint.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.units);
			refs.add(oid, PropertyIdentifier.presentValue);

		} else if (ObjectType.loop.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.outputUnits);
			refs.add(oid, PropertyIdentifier.presentValue);
		
		} else if (ObjectType.multiStateInput.equals(type)
				|| ObjectType.multiStateOutput.equals(type)
				|| ObjectType.multiStateValue.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.stateText);
			refs.add(oid, PropertyIdentifier.presentValue);
			refs.add(oid, PropertyIdentifier.covIncrement);
			refs.add(oid, PropertyIdentifier.statusFlags);
			refs.add(oid, PropertyIdentifier.outOfService);

		} else if (ObjectType.notificationClass.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.notificationClass);
			refs.add(oid, PropertyIdentifier.priority);
			refs.add(oid, PropertyIdentifier.ackRequired);
			refs.add(oid, PropertyIdentifier.recipientList);
			refs.add(oid, PropertyIdentifier.profileName);

			
					
			
			
		} else if (ObjectType.schedule.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			refs.add(oid, PropertyIdentifier.presentValue);
			refs.add(oid, PropertyIdentifier.scheduleDefault);
			refs.add(oid, PropertyIdentifier.effectivePeriod);
			refs.add(oid, PropertyIdentifier.exceptionSchedule);
			refs.add(oid, PropertyIdentifier.weeklySchedule);

		} else if (ObjectType.calendar.equals(type)) {
			refs.add(oid, PropertyIdentifier.description);
			
		} else
			return;

		
	}

	@Override
	public boolean allowPropertyWrite(Address from, BACnetObject obj,
			PropertyValue pv) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void propertyWritten(Address from, BACnetObject obj, PropertyValue pv) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void privateTransferReceived(Address from, UnsignedInteger vendorId,
			UnsignedInteger serviceNumber, Sequence serviceParameters) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void reinitializeDevice(Address from,
			ReinitializedStateOfDevice reinitializedStateOfDevice) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void synchronizeTime(Address from, DateTime dateTime, boolean utc) {
		// TODO Auto-generated method stub
		
	}

}
