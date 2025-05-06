#include "dex_logger.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <iterator>
#include <cstring>

// Define DEX constants
const uint8_t ENQ = 0x05;
const uint8_t ACK0[] = {0x10, 0x30};
const uint8_t ACK1[] = {0x10, 0x31};
const uint8_t DLE = 0x10;
const uint8_t SOH = 0x01;
const uint8_t ETX = 0x03;
const uint8_t EOT = 0x04;

// Placeholder - These should be loaded from config or defined
// const std::vector<uint8_t> VMD_CommunicationID = { 'C', 'O', 'M', 'M', 'I', 'D', '0', '1' }; // Example: 8 bytes - REMOVED
// const std::vector<uint8_t> VMD_RevisionLevel = { 'R', 'E', 'V', 'L', 'E', 'V', '0', '1' }; // Example: 8 bytes - REMOVED

DexLogger::DexLogger()
    : connectionManager_(nullptr)
    , dataLogger_(nullptr)
    , initialized_(false)
    , currentState_(State::IDLE)
    , currentConfigIndex_(0)
    , configLocked_(false)
{
}

DexLogger::~DexLogger() {
    if (initialized_) {
        stop();
    }
}

bool DexLogger::initialize(const std::string& configPath) {
    std::cout << "Initializing DEX Logger..." << std::endl;
    
    // Load configuration
    if (!config_.load(configPath)) {
        std::cerr << "Failed to load configuration from " << configPath << std::endl;
        return false;
    }
    
    std::cout << "Configuration loaded successfully" << std::endl;
    std::cout << "Connection config:" << std::endl;
    std::cout << "  Port: " << config_.getConnectionConfig().port << std::endl;
    std::cout << "  Baud Rate: " << config_.getConnectionConfig().baudRate << std::endl;
    std::cout << "Logging config:" << std::endl;
    std::cout << "  Log Directory: " << config_.getLoggingConfig().logDirectory << std::endl;
    
    // Initialize data logger with new config first
    dataLogger_ = std::make_unique<DataLogger>(config_.getLoggingConfig());
    dataLogger_->logSystemEvent("Initializing DEX Logger");
    dataLogger_->logSystemEvent("Configuration loaded successfully");
    dataLogger_->logSystemEvent("Connection config - Port: " + config_.getConnectionConfig().port + 
                              ", Baud Rate: " + std::to_string(config_.getConnectionConfig().baudRate));
    
    // Store all configurations for potential reconnection attempts
    allConfigs_.push_back(config_.getConnectionConfig());
    const auto& alternates = config_.getConnectionAlternates();
    allConfigs_.insert(allConfigs_.end(), alternates.begin(), alternates.end());
    currentConfigIndex_ = 0;

    // Initialize connection manager with the first config (primary)
    connectionManager_ = std::make_unique<ConnectionManager>(allConfigs_[0]);
    
    // Set up data callback for received data
    connectionManager_->setDataCallback([this](const uint8_t* data, size_t length) {
        this->handleData(data, length);
    });

    // Set up data callback for sent data
    connectionManager_->setSentDataCallback([this](const uint8_t* data, size_t length) {
        this->handleSentData(data, length);
    });
    
    initialized_ = true;
    return true;
}

bool DexLogger::start() {
    if (!initialized_) {
        std::cerr << "DexLogger not initialized" << std::endl;
        dataLogger_->logSystemEvent("ERROR: DexLogger not initialized");
        return false;
    }
    
    std::cout << "Starting connection manager..." << std::endl;
    dataLogger_->logSystemEvent("Starting connection manager");
    
    if (!connectionManager_->start()) {
        std::string error = "Failed to start connection manager: " + connectionManager_->getLastError();
        std::cerr << error << std::endl;
        dataLogger_->logSystemEvent("ERROR: " + error);
        return false;
    }
    std::cout << "Connection manager started successfully" << std::endl;
    dataLogger_->logSystemEvent("Connection manager started successfully");
    
    // Set initial state after successful connection
    currentState_ = State::WAITING_FOR_FIRST_ENQ;
    dataLogger_->logSystemEvent("State transition to WAITING_FOR_FIRST_ENQ");

    std::cout << "Starting data logger..." << std::endl;
    dataLogger_->logSystemEvent("Starting data logger");
    
    if (!dataLogger_->start()) {
        std::string error = "Failed to start data logger: " + dataLogger_->getLastError();
        std::cerr << error << std::endl;
        dataLogger_->logSystemEvent("ERROR: " + error);
        connectionManager_->stop();
        return false;
    }
    std::cout << "Data logger started successfully" << std::endl;
    dataLogger_->logSystemEvent("Data logger started successfully");
    
    return true;
}

void DexLogger::stop() noexcept {
    if (initialized_) {
        dataLogger_->logSystemEvent("Stopping DEX Logger");
        connectionManager_->stop();
        dataLogger_->logSystemEvent("DEX Logger stopped");
    }
}

void DexLogger::handleData(const uint8_t* data, size_t length) {
    // Log the received data
    if (initialized_ && dataLogger_) {
        dataLogger_->logData(data, length, DataLogger::LogDirection::RX);
    }
    
    // --- State Machine Logic --- 
    switch (currentState_) {
        case State::WAITING_FOR_FIRST_ENQ:
            if (length == 1 && data[0] == 0x05) { // Received ENQ
                dataLogger_->logSystemEvent("Received first ENQ, attempting to send DLE+ACK0");
                // DEX Standard ACK0 is DLE (0x10) followed by '0' (0x30)
                uint8_t dle_ack0[] = { 0x10, 0x30 }; 
                if (connectionManager_ && connectionManager_->sendData(dle_ack0, sizeof(dle_ack0))) {
                    lastAckSentTimestamp_ = std::chrono::steady_clock::now();
                    currentState_ = State::WAITING_FOR_ACK_RESPONSE; 
                    // Add a small delay after sending ACK0, similar to DEXDELAY
                    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // 50ms delay
                    // Now we wait for the VMC's communication ID message or another ENQ/timeout
                    dataLogger_->logSystemEvent("State transition to WAITING_FOR_ACK_RESPONSE (Waiting for VMC Comm ID / EOT)");
                } else {
                    dataLogger_->logSystemEvent("ERROR: Failed to send DLE+ACK0 (check previous system logs for details)");
                    currentState_ = State::FAILED;
                    dataLogger_->logSystemEvent("State transition to FAILED (DLE+ACK0 send error)");
                }
            } else {
                // Received something unexpected before ENQ
                dataLogger_->logSystemEvent("WARNING: Received unexpected data while waiting for first ENQ");
            }
            break;

        case State::WAITING_FOR_ACK_RESPONSE:
            if (length == 1 && data[0] == 0x05) { // Received another ENQ - Handshake Failed!
                dataLogger_->logSystemEvent("Received ENQ while waiting for VMC response after DLE+ACK0 - Handshake failed with current config.");
                tryNextConfig(); // Attempt to reconnect with the next configuration
            } else {
                // Received something else - THIS is where the VMC's response (Comm ID) should arrive
                // Expected format: DLE(10) SOH(01) <Payload> DLE(10) ETX(03) CRC(2 bytes)
                std::stringstream debugInfo;
                debugInfo << "DEBUG: Frame analysis - length: " << length
                          << ", first byte: " << std::hex << static_cast<int>(data[0])
                          << ", second byte: " << std::hex << static_cast<int>(data[1]);
                
                if (length >= 3) {
                    debugInfo << ", third-to-last: " << std::hex << static_cast<int>(data[length - 3])
                              << ", second-to-last: " << std::hex << static_cast<int>(data[length - 2])
                              << ", last byte: " << std::hex << static_cast<int>(data[length - 1]);
                }
                
                dataLogger_->logSystemEvent(debugInfo.str());
                dataLogger_->logSystemEvent("Received potential VMC Comm ID response.");
                
                // Try a broader check based on the exact format we're seeing in logs
                bool frameCheck = (length >= 23 && 
                                  data[0] == 0x10 && data[1] == 0x01 && 
                                  data[19] == 0x10 && data[20] == 0x03);
                
                // Log check result
                dataLogger_->logSystemEvent("Frame check result: " + std::string(frameCheck ? "PASS" : "FAIL"));
                
                if (frameCheck) {
                    // Hard-wire this for direct debugging - assuming we know the right structure
                    // Assuming CRC bytes are data[21] and data[22]
                    uint16_t receivedCRC = static_cast<uint16_t>(data[21]) | (static_cast<uint16_t>(data[22]) << 8);
                    
                    // Calculate CRC on the message body
                    uint16_t calculatedCRC = 0x0000;
                    for (size_t i = 0; i < 21; ++i) { // Iterate over DLE+SOH to DLE+ETX inclusive
                        calculatedCRC = dex_crc16(calculatedCRC, data[i]);
                    }
                    
                    // Format and log the CRC values                  
                    std::stringstream crcLog;
                    crcLog << "CRC Comparison - Received: 0x" << std::hex << receivedCRC
                           << ", Calculated: 0x" << std::hex << calculatedCRC;
                    dataLogger_->logSystemEvent(crcLog.str());
                    
                    // Re-enable CRC check for production
                    if (receivedCRC == calculatedCRC) { 
                        dataLogger_->logSystemEvent("CRC Check Passed. Storing VMC ID and Revision.");
                        
                        // Extract VMC Communication ID (Bytes 2-9, assuming 8 bytes)
                        vmcCommunicationID_.assign(data + 2, data + 10);
                        // Extract VMC Revision Level (Bytes 11-18, assuming 8 bytes and 'R' at index 10)
                        vmcRevisionLevel_.assign(data + 11, data + 19);
                        // Store the separator byte (index 10)
                        vmcSeparator_ = data[10];
                        
                        // Log extracted info (optional)
                        std::string commIdStr(vmcCommunicationID_.begin(), vmcCommunicationID_.end());
                        std::string revLvlStr(vmcRevisionLevel_.begin(), vmcRevisionLevel_.end());
                        dataLogger_->logSystemEvent("Stored VMC Comm ID: " + commIdStr);
                        dataLogger_->logSystemEvent("Stored VMC Rev Lvl: " + revLvlStr);
                        dataLogger_->logSystemEvent("Stored VMC Separator: 0x" + (std::stringstream() << std::hex << static_cast<int>(vmcSeparator_)).str() + " ('" + std::string(1, (char)vmcSeparator_) + "')");
                        if (vmcSeparator_ != 'R') {
                            dataLogger_->logSystemEvent("WARNING: Received non-standard separator byte from VMC.");
                        }
                        
                        // Send DLE+ACK1
                        dataLogger_->logSystemEvent("Sending DLE+ACK1"); // Removed debugging note
                        uint8_t dle_ack1[] = { 0x10, 0x31 };
                        
                        // Add a delay similar to the one after DLE+ACK0
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                        
                        if (connectionManager_ && connectionManager_->sendData(dle_ack1, sizeof(dle_ack1))) {
                            currentState_ = State::WAITING_FOR_EOT_AFTER_COMM_ID;
                            dataLogger_->logSystemEvent("State transition to WAITING_FOR_EOT_AFTER_COMM_ID");
                            // Lock the configuration since the handshake is proceeding
                            if (!configLocked_) {
                                configLocked_ = true;
                                dataLogger_->logSystemEvent("Serial configuration locked due to successful handshake progress.");
                            }
                        } else {
                            dataLogger_->logSystemEvent("ERROR: Failed to send DLE+ACK1");
                            currentState_ = State::FAILED;
                            dataLogger_->logSystemEvent("State transition to FAILED (DLE+ACK1 send error)");
                        }
                    } else { // CRC Check Failed
                        dataLogger_->logSystemEvent("ERROR: CRC check failed for VMC Comm ID response.");
                        // Do NOT send ACK1. Transition to FAILED or try next config.
                        // For now, go directly to FAILED.
                        currentState_ = State::FAILED;
                        dataLogger_->logSystemEvent("State transition to FAILED (First handshake CRC error)");
                    }
                } else { // Frame Check Failed
                    dataLogger_->logSystemEvent("ERROR: Received unexpected frame structure while waiting for VMC Comm ID.");
                    currentState_ = State::FAILED;
                    dataLogger_->logSystemEvent("State transition to FAILED (First handshake CRC error)");
                }
            }
            break;

        case State::WAITING_FOR_EOT_AFTER_COMM_ID:
             if (length == 1 && data[0] == 0x04) { // Received EOT
                 dataLogger_->logSystemEvent("Received EOT after DLE+ACK1. First handshake complete.");
                 currentState_ = State::READY_FOR_SECOND_HANDSHAKE;
                 dataLogger_->logSystemEvent("State transition to READY_FOR_SECOND_HANDSHAKE");
                 // Initiate the second handshake immediately
                 performSecondHandshake();
             } else {
                 dataLogger_->logSystemEvent("WARNING: Received unexpected data while waiting for EOT after Comm ID");
                 // TODO: Decide how to handle unexpected data here
             }
             break;

        case State::READY_FOR_SECOND_HANDSHAKE:
            // This state is transient, performSecondHandshake() is called upon entry.
            // We might receive unexpected data here before the handshake response.
            dataLogger_->logSystemEvent("WARNING: Received unexpected data while ready for second handshake.");
            break;

        case State::WAITING_FOR_SECOND_ACK0:
            if (length == sizeof(ACK0) && memcmp(data, ACK0, sizeof(ACK0)) == 0) { // Received DLE+ACK0
                dataLogger_->logSystemEvent("Received DLE+ACK0 for second handshake.");
                // Prepare the message with communication ID and revision level *received from VMC*
                
                // Log details being sent
                std::string commIdToSend(vmcCommunicationID_.begin(), vmcCommunicationID_.end());
                std::string revLvlToSend(vmcRevisionLevel_.begin(), vmcRevisionLevel_.end());
                dataLogger_->logSystemEvent("Constructing second handshake message with:");
                dataLogger_->logSystemEvent("  Comm ID: " + commIdToSend);
                dataLogger_->logSystemEvent("  Separator: 0x" + (std::stringstream() << std::hex << static_cast<int>(vmcSeparator_)).str() + " ('" + std::string(1, (char)vmcSeparator_) + "')");
                dataLogger_->logSystemEvent("  Rev Lvl: " + revLvlToSend);
                
                std::vector<uint8_t> message;
                message.push_back(DLE);
                message.push_back(SOH);
                // Use stored VMC details
                message.insert(message.end(), vmcCommunicationID_.begin(), vmcCommunicationID_.end());
                // message.push_back('R'); // Separator 'R' - Use the stored separator instead
                message.push_back(vmcSeparator_); // Use the separator byte received from VMC
                message.insert(message.end(), vmcRevisionLevel_.begin(), vmcRevisionLevel_.end());
                message.push_back(DLE);
                message.push_back(ETX);

                // Calculate CRC
                uint16_t crc = 0x0000;
                for (uint8_t byte : message) {
                    crc = dex_crc16(crc, byte);
                }
                uint8_t crc_bytes[2];
                crc_bytes[0] = crc & 0xFF;          // Low byte
                crc_bytes[1] = (crc >> 8) & 0xFF; // High byte

                // Combine message and CRC
                message.insert(message.end(), crc_bytes, crc_bytes + sizeof(crc_bytes));

                dataLogger_->logSystemEvent("Sending Comm ID/Revision Level for second handshake.");
                if (connectionManager_ && connectionManager_->sendData(message.data(), message.size())) {
                     // Optional short delay
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    currentState_ = State::WAITING_FOR_SECOND_ACK1;
                    dataLogger_->logSystemEvent("State transition to WAITING_FOR_SECOND_ACK1");
                } else {
                    dataLogger_->logSystemEvent("ERROR: Failed to send Comm ID/Revision Level for second handshake.");
                    currentState_ = State::FAILED;
                    dataLogger_->logSystemEvent("State transition to FAILED (Second handshake send error)");
                }
            } else {
                 dataLogger_->logSystemEvent("ERROR: Did not receive expected DLE+ACK0 for second handshake.");
                 // TODO: Handle failure - retry? go to FAILED state?
                 currentState_ = State::FAILED;
                 dataLogger_->logSystemEvent("State transition to FAILED (Second handshake ACK0 error)");
            }
            break;

        case State::WAITING_FOR_SECOND_ACK1:
             if (length == sizeof(ACK1) && memcmp(data, ACK1, sizeof(ACK1)) == 0) { // Received DLE+ACK1
                 dataLogger_->logSystemEvent("Received DLE+ACK1 after sending Comm ID/Revision.");
                 // Send EOT to finalize the second handshake
                 dataLogger_->logSystemEvent("Sending EOT to finalize second handshake.");
                 uint8_t eot_byte = EOT;
                 if (connectionManager_ && connectionManager_->sendData(&eot_byte, 1)) {
                      // Optional short delay
                     std::this_thread::sleep_for(std::chrono::milliseconds(50));
                     currentState_ = State::COMMUNICATING; // Handshake complete, ready for data exchange
                     dataLogger_->logSystemEvent("Second Handshake successful. State transition to COMMUNICATING.");
                 } else {
                     dataLogger_->logSystemEvent("ERROR: Failed to send EOT for second handshake.");
                     currentState_ = State::FAILED;
                     dataLogger_->logSystemEvent("State transition to FAILED (Second handshake EOT send error)");
                 }
             } else {
                 dataLogger_->logSystemEvent("ERROR: Did not receive expected DLE+ACK1 for second handshake.");
                 // TODO: Handle failure
                 currentState_ = State::FAILED;
                 dataLogger_->logSystemEvent("State transition to FAILED (Second handshake ACK1 error)");
             }
             break;

        case State::WAITING_FOR_EOT_AFTER_SECOND_HANDSHAKE:
            // This state might not be strictly necessary if we transition directly to COMMUNICATING after sending EOT
            // But if the VMC sends something unexpected after our EOT, it would be caught here.
            dataLogger_->logSystemEvent("WARNING: Received unexpected data after sending final EOT of second handshake.");
            // Perhaps transition back to COMMUNICATING or handle error?
            currentState_ = State::COMMUNICATING;
            dataLogger_->logSystemEvent("State transition to COMMUNICATING (Ignoring post-EOT data)");
            break;

        case State::COMMUNICATING:
            // TODO: Handle ongoing data exchange (DLE stuffing, EOT, checksums)
            dataLogger_->logSystemEvent("Received data while communicating.");
            // Process the received data (data, length)
            if (length == 1 && data[0] == 0x04) { // Example: Received EOT
                 dataLogger_->logSystemEvent("Received EOT. Transaction likely complete.");
                 currentState_ = State::WAITING_FOR_FIRST_ENQ; // Go back to waiting for next transaction
                 dataLogger_->logSystemEvent("State transition back to WAITING_FOR_FIRST_ENQ");
            }
            break;

        case State::CONNECTING:
        case State::RECONNECTING:
            // Should not typically receive data in these states, but log if we do
            dataLogger_->logSystemEvent("WARNING: Received data unexpectedly during (re)connection phase.");
            break;

        case State::IDLE:
        case State::INITIALIZING:
        case State::FAILED:
            // Ignore data received in these states
            break;
    }
}

void DexLogger::handleSentData(const uint8_t* data, size_t length) {
    // Log the sent data
    if (initialized_ && dataLogger_) {
        dataLogger_->logData(data, length, DataLogger::LogDirection::TX);
    }
    // Optional: Could update state based on what was sent if needed
}

void DexLogger::checkTimeouts() {
    if (currentState_ == State::WAITING_FOR_ACK_RESPONSE) {
        auto now = std::chrono::steady_clock::now();
        if (now - lastAckSentTimestamp_ > HANDSHAKE_TIMEOUT) {
            dataLogger_->logSystemEvent("Handshake timed out waiting for VMC response after DLE+ACK0.");
            tryNextConfig(); // Attempt to reconnect with the next configuration
        }
    }
    // Can add other timeouts here if needed (e.g., overall connection timeout)
}

// Helper function to attempt reconnection with the next configuration
void DexLogger::tryNextConfig() {
    if (!connectionManager_) return;

    // If config is locked, don't try alternates
    if (configLocked_) {
        dataLogger_->logSystemEvent("Configuration locked. Handshake failed permanently for this session.");
        currentState_ = State::FAILED;
        dataLogger_->logSystemEvent("State transition to FAILED (Config Locked)");
        return;
    }

    currentConfigIndex_++;
    if (currentConfigIndex_ < allConfigs_.size()) {
        dataLogger_->logSystemEvent("Attempting reconnection with config index " + std::to_string(currentConfigIndex_));
        currentState_ = State::RECONNECTING;
        dataLogger_->logSystemEvent("State transition to RECONNECTING");
        
        if (connectionManager_->reconnect(allConfigs_[currentConfigIndex_])) {
            currentState_ = State::WAITING_FOR_FIRST_ENQ; // Success, wait for VMC again
            dataLogger_->logSystemEvent("Reconnection successful. State transition to WAITING_FOR_FIRST_ENQ");
        } else {
            // Reconnect failed, try the next one immediately (or could add delay)
            dataLogger_->logSystemEvent("Reconnect attempt failed for config index " + std::to_string(currentConfigIndex_));
            // Recursive call might be okay for a few configs, but loop is safer for many
            // For simplicity here, let's assume checkTimeouts or next ENQ will call tryNextConfig again if needed
            // Or directly try next:
            tryNextConfig(); 
        }
    } else {
        dataLogger_->logSystemEvent("All configurations attempted. Handshake failed.");
        currentState_ = State::FAILED;
        dataLogger_->logSystemEvent("State transition to FAILED (All configs tried)");
        // Optionally stop the logger or enter a permanent failed state
        // stop(); 
    }
}

bool DexLogger::runTestMode() {
    if (!initialized_) {
        std::cerr << "DexLogger not initialized" << std::endl;
        return false;
    }
    
    std::cout << "\nRunning DEX Logger Test Mode\n"
              << "===========================\n" << std::endl;
    
    // Test configuration
    std::cout << "1. Configuration Test\n"
              << "   ----------------" << std::endl;
    std::cout << "   Connection Config:" << std::endl;
    std::cout << "   - Port: " << config_.getConnectionConfig().port << std::endl;
    std::cout << "   - Baud Rate: " << config_.getConnectionConfig().baudRate << std::endl;
    std::cout << "   Logging Config:" << std::endl;
    std::cout << "   - Log Directory: " << config_.getLoggingConfig().logDirectory << std::endl;
    std::cout << "   - Rotation Interval: " << config_.getLoggingConfig().rotationInterval << " minutes" << std::endl;
    
    // Test port detection
    std::cout << "\n2. Port Detection Test\n"
              << "   ------------------" << std::endl;
    auto ports = connectionManager_->getAvailablePorts();
    if (ports.empty()) {
        std::cout << "   No serial ports detected" << std::endl;
    } else {
        std::cout << "   Available ports:" << std::endl;
        for (const auto& port : ports) {
            std::cout << "   - " << port << std::endl;
        }
    }
    
    // Test port configuration
    std::cout << "\n3. Port Configuration Test\n"
              << "   ----------------------" << std::endl;
    if (connectionManager_->testConfiguration()) {
        std::cout << "   Port configuration successful" << std::endl;
    } else {
        std::cout << "   Port configuration failed" << std::endl;
        return false;
    }
    
    std::cout << "\nTest mode completed successfully" << std::endl;
    return true;
}

void DexLogger::setVerbosity(ConnectionManager::DiagnosticLevel level) {
    if (initialized_) {
        connectionManager_->setDiagnosticLevel(level);
    }
}

std::string DexLogger::getStatus() const noexcept {
    std::stringstream ss;
    ss << "DEX Logger Status:\n"
       << "- Initialized: " << (initialized_ ? "Yes" : "No") << "\n"
       << "- Connection Manager: " << (connectionManager_->isConnected() ? "Connected" : "Disconnected") << "\n"
       << "- Last Error: " << connectionManager_->getLastError();
    return ss.str();
}

// --- Second Handshake Initiation --- 
bool DexLogger::performSecondHandshake() {
    dataLogger_->logSystemEvent("Initiating second handshake: Sending ENQ.");
    uint8_t enq_byte = ENQ;
    if (connectionManager_ && connectionManager_->sendData(&enq_byte, 1)) {
        // Transition state to wait for ACK0
        currentState_ = State::WAITING_FOR_SECOND_ACK0;
        dataLogger_->logSystemEvent("State transition to WAITING_FOR_SECOND_ACK0");
        return true;
    } else {
        dataLogger_->logSystemEvent("ERROR: Failed to send ENQ for second handshake.");
        currentState_ = State::FAILED;
        dataLogger_->logSystemEvent("State transition to FAILED (Second handshake ENQ send error)");
        return false;
    }
}

// --- CRC Calculation ---
// Calculates DEX CRC-16 CCITT (False) - based on Python simulator code
uint16_t DexLogger::dex_crc16(uint16_t dwCRC, uint8_t byte) {
    for (int j = 0; j < 8; ++j) {
        bool dataBit = (byte >> j) & 0x01;
        bool crcBit0 = dwCRC & 0x0001;
        bool crcBit1 = (dwCRC >> 1) & 0x0001;
        bool crcBit14 = (dwCRC >> 14) & 0x0001;

        bool x16 = crcBit0 ^ dataBit;
        bool x15 = crcBit1 ^ x16;
        bool x2 = crcBit14 ^ x16;

        dwCRC >>= 1;          // Shift right
        dwCRC &= 0x5FFE;      // Clear bits 0, 13, 15 (effectively)

        if (x15) dwCRC |= 0x0001; // Set bit 0 based on x15
        if (x2)  dwCRC |= 0x2000; // Set bit 13 based on x2
        if (x16) dwCRC |= 0x8000; // Set bit 15 based on x16
    }
    return dwCRC;
} 