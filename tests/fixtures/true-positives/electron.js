// True-positive fixtures for Electron patterns
const { BrowserWindow } = require("electron");

const win = new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,
    contextIsolation: false
  }
});
