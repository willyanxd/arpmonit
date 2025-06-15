import { spawn } from 'child_process';
import { promisify } from 'util';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

export class ArpScanner {
  constructor() {
    this.isRunning = false;
  }

  /**
   * Perform ARP scan on specified subnet using specified interface
   * @param {string} interface - Network interface to use
   * @param {string} subnet - Subnet to scan (e.g., '192.168.1.0/24')
   * @param {number} timeout - Timeout in seconds
   * @returns {Promise<Array>} Array of discovered devices
   */
  async scan(interface, subnet, timeout = 5) {
    if (this.isRunning) {
      throw new Error('ARP scan already in progress');
    }

    this.isRunning = true;
    logger.info(`Starting ARP scan on ${interface} for subnet ${subnet}`);

    try {
      const devices = await this._executeScan(interface, subnet, timeout);
      logger.info(`ARP scan completed. Found ${devices.length} devices`);
      return devices;
    } catch (error) {
      logger.error('ARP scan failed:', error);
      throw error;
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Execute the actual arp-scan command
   * @private
   */
  async _executeScan(interface, subnet, timeout) {
    return new Promise((resolve, reject) => {
      const args = [
        '-I', interface,    // Interface
        '-t', (timeout * 1000).toString(), // Timeout in milliseconds
        '--format', '${ip}\t${mac}\t${vendor}', // Custom format
        '--plain',          // No headers
        '--quiet',          // Minimal output
        subnet              // Target subnet
      ];

      logger.debug(`Executing: arp-scan ${args.join(' ')}`);

      const process = spawn('arp-scan', args, {
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      process.on('close', (code) => {
        if (code !== 0) {
          logger.error(`arp-scan exited with code ${code}: ${stderr}`);
          reject(new Error(`arp-scan failed with exit code ${code}: ${stderr}`));
          return;
        }

        try {
          const devices = this._parseOutput(stdout);
          resolve(devices);
        } catch (error) {
          reject(error);
        }
      });

      process.on('error', (error) => {
        logger.error('Failed to start arp-scan process:', error);
        reject(new Error(`Failed to execute arp-scan: ${error.message}`));
      });

      // Set overall timeout
      setTimeout(() => {
        if (!process.killed) {
          process.kill('SIGTERM');
          reject(new Error('ARP scan timed out'));
        }
      }, (timeout + 10) * 1000); // Add 10 seconds buffer
    });
  }

  /**
   * Parse arp-scan output
   * @private
   */
  _parseOutput(output) {
    const devices = [];
    const lines = output.trim().split('\n');

    for (const line of lines) {
      if (line.trim() === '') continue;
      
      const parts = line.split('\t');
      if (parts.length >= 2) {
        const device = {
          ip: parts[0].trim(),
          mac: parts[1].trim().toLowerCase(),
          vendor: parts[2] ? parts[2].trim() : 'Unknown',
          detected_at: new Date().toISOString()
        };

        // Validate IP and MAC formats
        if (this._isValidIP(device.ip) && this._isValidMAC(device.mac)) {
          devices.push(device);
        } else {
          logger.warn(`Invalid device data: ${line}`);
        }
      }
    }

    return devices;
  }

  /**
   * Validate IP address format
   * @private
   */
  _isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  }

  /**
   * Validate MAC address format
   * @private
   */
  _isValidMAC(mac) {
    const macRegex = /^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$/i;
    return macRegex.test(mac);
  }

  /**
   * Check if arp-scan is available on the system
   */
  static async checkAvailability() {
    return new Promise((resolve) => {
      const process = spawn('which', ['arp-scan']);
      
      process.on('close', (code) => {
        resolve(code === 0);
      });
      
      process.on('error', () => {
        resolve(false);
      });
    });
  }

  /**
   * Get version information
   */
  static async getVersion() {
    return new Promise((resolve, reject) => {
      const process = spawn('arp-scan', ['--version']);
      
      let output = '';
      
      process.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        output += data.toString();
      });
      
      process.on('close', (code) => {
        if (code === 0) {
          resolve(output.trim());
        } else {
          reject(new Error('Failed to get arp-scan version'));
        }
      });
      
      process.on('error', (error) => {
        reject(error);
      });
    });
  }
}