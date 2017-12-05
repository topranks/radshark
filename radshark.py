#!/usr/bin/python3
import argparse
import pyshark
import time

def parseFile(args):
    pcap_file = pyshark.FileCapture(args.file)

    # Dictionary to hold "open" requests - where we've got REQ 
    # and are expecting to see a subsequent RESP:
    open_requests = {}
    # Dict of sessions, keyed by pri_key (username, acct_session_id etc.)
    radius_sessions = {}

    for packet in pcap_file:
        if('RADIUS' in packet):
            radius_code=int(packet['radius'].Code)

            # Access Request:
            if(radius_code==1):
                src_ip=packet['ip'].src
                radius_id=packet['radius'].id

                # Put it in the "open requests" dict while we await response:
                if src_ip in open_requests:
                    open_requests[src_ip][radius_id]=packet
                else:
                    open_requests[src_ip]={}
                    open_requests[src_ip][radius_id]=packet


            # Access Response: 
            elif(radius_code==2 or radius_code==3):
                src_ip=packet['ip'].dst
                radius_id=packet['radius'].id

                try:
                    # Get associated access_req from open_requests:
                    access_req_packet=open_requests[src_ip][radius_id]
                    # Delete this packet from 'open_requests' as we've found response:
                    del open_requests[src_ip][radius_id]

                    # Get acct-id of initial request:
                    acct_session_id=access_req_packet['radius'].acct_session_id

                    # Store request + response in dict of sessions:
                    radius_sessions[acct_session_id]={}
                    radius_sessions[acct_session_id]['req']=access_req_packet
                    radius_sessions[acct_session_id]['resp']=packet       

                except KeyError:
                    # We never seen an Access Req for this, so can't record it.
                    pass    

 
            # Accounting Packet:
            elif(radius_code==4):
                # Get packet type and acct-id:
                acct_type=int(packet['radius'].acct_status_type)
                acct_session_id=packet['radius'].acct_session_id
                 
                # Accounting Start
                if(acct_type==1):
                    try:
                        radius_sessions[acct_session_id]['acct_start']=packet
                    except KeyError:
                        pass
                elif(acct_type==2):
                    try:
                        radius_sessions[acct_session_id]['acct_stop']=packet
                    except KeyError:
                        pass

    return radius_sessions

def output_csv(radius_sessions):
    req_attributes=[]
    acct_start_attributes=[]
    acct_stop_attributes=[]

    for acct_id, session in radius_sessions.items():
        # This is stupid, parse every session and extract all potential attributes / column headings:
        
        # Add attributes from Access Req:
        for attribute in session['req']['radius'].field_names:
            if attribute not in req_attributes:
                req_attributes.append(attribute)
        try:
            # Add attributes from Acct Start:
            for attribute in session['acct_start']['radius'].field_names:
                if attribute not in acct_start_attributes:
                    acct_start_attributes.append(attribute)
            # Add attributes from Acct Stop:
            for attribute in session['acct_stop']['radius'].field_names:
                if attribute not in acct_stop_attributes:
                    acct_stop_attributes.append(attribute)
        except KeyError:
            # No Acct Start/Stop for this session:
            pass

    # Print top line of headings with all the attributes:
    for attribute in req_attributes:
        print("REQ_{0},".format(attribute), end='')
    print("RESP_Code,", end='')
    for attribute in acct_start_attributes:         
        print("START_{0},".format(attribute), end='')
    for attribute in acct_stop_attributes:
        print("STOP_{0},".format(attribute), end='')
    print("")


    for acct_id, session in radius_sessions.items():
        #  Iterate the same dict again (sigh), output CSV for each attribute possible:
        session_csv=""

        # Output text plus comma for each potential attribute in request.
        # Pyshark will return "none" if not present, giving us our spacer.
        for attribute in req_attributes:
            session_csv = session_csv + "{0},".format(str(session['req']['radius'].get_field_value(attribute)).replace(",", " "))
    
        # Check if response is Accept or Reject:
        response_type=int(session['resp']['radius'].Code)
        if(response_type==3):
            session_csv = session_csv + "REJECT"
        elif(response_type==2):
            session_csv = session_csv + "ACCEPT,"
            try:
                # To add details from accounting start:
                for attribute in acct_start_attributes:
                    session_csv = session_csv + "{0},".format(str(session['acct_start']['radius'].get_field_value(attribute)).replace(",", " "))
                for attribute in acct_stop_attributes:
                    session_csv = session_csv + "{0},".format(str(session['acct_stop']['radius'].get_field_value(attribute)).replace(",", " "))
            except KeyError:
                # There was no account start or stop captured for this session:
                pass

        # Print CSV line for this session and loop back around:
        print(session_csv)


if __name__ == "__main__":
    # Set up CLI argument:
    parser = argparse.ArgumentParser(description='Stupid Radius PCAP file Statistics Shite')
    parser.add_argument('-f', '--file', help='PCAP file to read from', type=str)

    radius_sessions=parseFile(parser.parse_args())

    output_csv(radius_sessions)

