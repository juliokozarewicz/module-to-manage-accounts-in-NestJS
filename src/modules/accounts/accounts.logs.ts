import * as fs from 'fs';
import * as path from 'path';

const logsDir = path.resolve('./src/modules/logs');
const logFilePath = path.resolve('./src/modules/logs/0_logs.txt');

function createDir() {
    try {
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
            console.log(`Logs directory created at: ${logsDir}`);
        }
        if (!fs.existsSync(logFilePath)) {
            fs.writeFileSync(logFilePath, '');
            console.log(`Logs file created at: ${logFilePath}`);
        }
    } catch (error) {
        console.error('Error creating logs directory or file:', error);
        throw error;
    }
}

export async function logsGenerator(level: string, message: string) {
    const timestamp = new Date().toLocaleString();
    const logMessage = `${timestamp}, ${level.toUpperCase()}, ${message}\n`;

    try {
        createDir()
        await fs.promises.appendFile(logFilePath, logMessage);
    } catch (error) {
        console.error('Error writing to log file:', error);
    }
}