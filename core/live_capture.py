"""
BENFET Core - Live Packet Capture
Captures real-time network traffic and saves to PCAP files.
Supports interface selection, duration-based capture, and packet count limits.
"""

import os
import time
import threading
from datetime import datetime
from config import UPLOAD_FOLDER

# Optional Scapy support; this module can still run with simulated capture if Scapy is not installed.
try:
    from scapy.all import conf
    SCAPY_AVAILABLE = True
except Exception as err:
    print(f"[LIVE_CAPTURE] Scapy unavailable: {err}")
    SCAPY_AVAILABLE = False

# Global state for live capture
_state_lock = threading.Lock()
_capture_state = {
    'is_capturing': False,
    'thread': None,
    'packets_captured': 0,
    'start_time': None,
    'output_file': None,
    'error': None,
    'stop_event': None,
    'duration_target': 0,
    'packet_target': 0,
    'capture_backend': 'unknown',
}


def get_interfaces():
    """
    List available network interfaces for capture.
    Returns a list of interface dicts with name and description.
    """
    interfaces = []

    if not SCAPY_AVAILABLE:
        # Data can't be discovered dynamically without Scapy, return safe defaults.
        return [
            {'name': 'Ethernet', 'description': 'Default Ethernet'},
            {'name': 'Wi-Fi', 'description': 'Default Wi-Fi'},
        ]

    try:
        # Check if we have proper packet capture capability
        if not getattr(conf, 'use_pcap', False):
            print("WARNING: No packet capture library (Npcap/WinPcap) detected.")
            print("Live capture will require administrator privileges or limited functionality.")
            print("Download and install Npcap from: https://npcap.com/#download")

        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            for iface in win_ifaces:
                interfaces.append({
                    'name': iface['name'],
                    'description': iface['description'] or iface['name'],
                })
        else:
            from scapy.all import get_if_list
            for iface in get_if_list():
                interfaces.append({
                    'name': iface,
                    'description': iface,
                })
    except Exception as e:
        print(f"[LIVE_CAPTURE] get_interfaces exception: {e}")
        interfaces = [
            {'name': 'Ethernet', 'description': 'Default Ethernet'},
            {'name': 'Wi-Fi', 'description': 'Default Wi-Fi'},
        ]
    return interfaces


# Alias for API compatibility
get_available_interfaces = get_interfaces


def start_capture(interface=None, duration=120, packet_count=5000, filename=None, mode='live'):
    """
    Start capturing packets on a network interface.

    Args:
        interface: Network interface name (None = auto-select first available)
        duration: Capture duration in seconds (default 120)
        packet_count: Max packets to capture (default 5000)
        filename: Output PCAP filename (auto-generated if None)

    Returns:
        dict with capture session info
    """
    print(f"\n[CAPTURE API] start_capture called - interface={interface}, duration={duration}, max_packets={packet_count}")
    
    with _state_lock:
        if _capture_state['is_capturing']:
            print("[CAPTURE API] Capture already in progress!")
            elapsed = 0
            if _capture_state['start_time']:
                elapsed = round(time.time() - _capture_state['start_time'], 2)
            return {
                'error': 'Capture already in progress',
                'status': 'busy',
                'packets_captured': _capture_state['packets_captured'],
                'elapsed_seconds': elapsed,
                'filepath': _capture_state['output_file'],
            }

    # Auto-select interface if none specified
    if interface is None:
        interfaces = get_interfaces()
        print(f"[CAPTURE API] Auto-detecting interface from {len(interfaces)} available")
        if interfaces:
            interface = interfaces[0]['name']  # Use first available interface
            print(f"[CAPTURE API] Selected interface: {interface}")
        else:
            print("[CAPTURE API] No interfaces available!")
            return {'error': 'No network interfaces available', 'status': 'error'}

    if filename is None:
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    output_path = os.path.join(UPLOAD_FOLDER, filename)
    stop_event = threading.Event()

    # If Scapy or libpcap is unavailable, fail fast (no synthetic fallback)
    if not SCAPY_AVAILABLE:
        err = 'Scapy not installed. Live capture unavailable.'
        print(f"[CAPTURE API] {err}")
        return {'status': 'failed', 'error': err, 'capture_backend': 'unavailable'}

    with _state_lock:
        _capture_state.update({
            'is_capturing': True,
            'packets_captured': 0,
            'start_time': time.time(),
            'output_file': output_path,
            'error': None,
            'stop_event': stop_event,
            'duration_target': duration,
            'packet_target': packet_count,
            'capture_backend': mode or 'live',
        })

    # Run capture in background thread
    thread = threading.Thread(
        target=_capture_thread,
        args=(interface, duration, packet_count, output_path, stop_event, mode),
        daemon=True,
    )
    _capture_state['thread'] = thread
    thread.start()
    print(f"[CAPTURE API] Thread started successfully")

    return {
        'status': 'capturing',
        'filename': filename,
        'filepath': output_path,
        'interface': interface,
        'duration': duration,
        'max_packets': packet_count,
    }


def stop_capture():
    """Stop an active capture session and return results."""
    with _state_lock:
        # Guard: if start_time is None the capture was never started or already stopped
        start_time = _capture_state.get('start_time')
        if start_time is None and not _capture_state['is_capturing']:
            # Return last known result instead of an error so the frontend flow doesn't break
            return {
                'status': 'stopped',
                'packets_captured': _capture_state['packets_captured'],
                'output_file': _capture_state['output_file'],
                'duration': 0,
                'error': None,
            }

        if _capture_state['stop_event']:
            _capture_state['stop_event'].set()

        thread = _capture_state.get('thread')

    # Wait for thread to finish outside lock to avoid deadlock
    if thread and thread.is_alive():
        thread.join(timeout=5)

    with _state_lock:
        # Safe duration calc — start_time may have been cleared by thread's finally block
        elapsed = 0
        if start_time is not None:
            elapsed = round(time.time() - start_time, 2)

        result = {
            'status': 'stopped',
            'packets_captured': _capture_state['packets_captured'],
            'output_file': _capture_state['output_file'],
            'duration': elapsed,
            'error': _capture_state['error'],
        }

        # Clear state so it can't be stopped again and frees up for next capture
        _capture_state['is_capturing'] = False
        _capture_state['start_time'] = None
        _capture_state['thread'] = None
        _capture_state['output_file'] = None
        _capture_state['duration_target'] = 0
        _capture_state['packet_target'] = 0
        _capture_state['capture_backend'] = 'unknown'

    return result


def get_capture_status():
    """Get the current capture status."""
    with _state_lock:
        elapsed = 0
        if _capture_state['start_time'] and _capture_state['is_capturing']:
            elapsed = round(time.time() - _capture_state['start_time'], 2)

        packets_captured = int(_capture_state['packets_captured'] or 0)
        display_packets_captured = packets_captured
        duration_target = float(_capture_state.get('duration_target') or 0)
        packet_target = int(_capture_state.get('packet_target') or 0)
        is_capturing = _capture_state['is_capturing']
        output_file = _capture_state['output_file']
        error = _capture_state['error']
        capture_backend = _capture_state.get('capture_backend', 'unknown')

    # Provide a visible progress counter while capture is active, especially
    # during synthetic/fallback capture where packet bursts may not align with
    # every UI polling interval.
    if is_capturing and display_packets_captured == 0 and duration_target > 0 and packet_target > 0:
        estimated = int(min(packet_target, (elapsed / duration_target) * packet_target))
        display_packets_captured = max(0, estimated)

    return {
        'is_capturing': is_capturing,
        'packets_captured': packets_captured,
        'display_packets_captured': display_packets_captured,
        'elapsed_seconds': elapsed,
        'output_file': output_file,
        'error': error,
        'capture_backend': capture_backend,
    }


def _capture_thread(interface, duration, packet_count, output_path, stop_event, mode='live'):
    """Background thread that performs the actual packet capture."""
    if not SCAPY_AVAILABLE:
        _capture_state['error'] = 'Scapy not installed — cannot perform live capture.'
        print(f"[CAPTURE] {_capture_state['error']}")
        _capture_state['is_capturing'] = False
        return

    try:
        from scapy.all import sniff, conf
        from scapy.utils import PcapWriter

        print(f"[CAPTURE] Starting capture thread on interface: {interface}")
        print(f"[CAPTURE] Duration: {duration}s, Max packets: {packet_count}")
        print(f"[CAPTURE] Libpcap available: {getattr(conf, 'use_pcap', False)}")

        # Use a streaming writer to avoid keeping packets in memory
        writer = None

        def _stop_filter(pkt):
            """Stop filter: returns True when capture should stop."""
            if stop_event.is_set():
                return True
            with _state_lock:
                if int(_capture_state.get('packets_captured') or 0) >= packet_count:
                    return True
                if time.time() - _capture_state.get('start_time', time.time()) >= duration:
                    return True
            return False

        def _packet_callback(pkt):
            try:
                # Lazily create writer so we don't touch disk until we have data
                nonlocal writer
                if writer is None:
                    writer = PcapWriter(output_path, append=False, sync=True)
                writer.write(pkt)
            except Exception as e:
                print(f"[CAPTURE] Error writing packet to pcap: {e}")
            finally:
                with _state_lock:
                    _capture_state['packets_captured'] = int((_capture_state.get('packets_captured') or 0)) + 1

        # Capture packets
        # NOTE: On Windows, specifying interface by device name DOES work with Npcap
        # Npcap uses \Device\NPF_{GUID} format
        kwargs = {
            'prn': _packet_callback,
            'stop_filter': _stop_filter,
            'timeout': duration,
            'store': 0,  # Don't keep packets in memory during capture (callback handles it)
        }
        
        # Use the interface if provided (including Device paths)
        if interface:
            kwargs['iface'] = interface
            print(f"[CAPTURE] Using interface: {interface}")

        # On Windows without WinPcap/Npcap (libpcap provider), scapy cannot perform
        # layer 2 capture. Fail instead of generating synthetic data.
        if not getattr(conf, "use_pcap", False):
            _capture_state['error'] = 'Npcap/WinPcap not available — live capture unsupported.'
            print(f"[CAPTURE] {_capture_state['error']}")
            _capture_state['is_capturing'] = False
            return

        print("[CAPTURE] Starting sniff (synchronous block)...")
        start_t = time.time()
        try:
            sniff(prn=_packet_callback, stop_filter=_stop_filter, timeout=duration, store=0, iface=interface if interface else None)
        finally:
            with _state_lock:
                print(f"[CAPTURE] Sniff loop completed. Captured {_capture_state.get('packets_captured', 0)} packets.")

        # Close writer if it was created
        if writer is not None:
            try:
                writer.close()
                print(f"[CAPTURE] Successfully saved PCAP file to {output_path}")
            except Exception as write_err:
                print(f"[CAPTURE] ERROR closing PCAP writer: {write_err}")
                raise Exception(f"Failed to finalize PCAP file: {write_err}") from write_err

        # If no packets were captured, set an error and stop. No synthetic fallback.
        with _state_lock:
            if int(_capture_state.get('packets_captured', 0)) == 0:
                _capture_state['error'] = 'No live packets captured within the requested interval.'
                print(f"[CAPTURE] {_capture_state['error']}")
                _capture_state['is_capturing'] = False
                return

    except PermissionError as e:
        with _state_lock:
            _capture_state['error'] = f"Permission error during sniff: {e}"
            print(f"[CAPTURE] {_capture_state['error']}")
    except Exception as e:
        with _state_lock:
            _capture_state['error'] = f"Sniff exception: {e}"
            print(f"[CAPTURE] {_capture_state['error']}")
    finally:
        with _state_lock:
            print("[CAPTURE] Thread cleanup - setting is_capturing to False")
            _capture_state['is_capturing'] = False


# Synthetic capture removed: live-only capture is enforced to keep OTX/api safe.


