const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { app, BrowserWindow, nativeImage } = require('electron');

const rootDir = path.resolve(__dirname, '..');
const svgPath = path.join(rootDir, 'assets', 'icon.svg');
const pngPath = path.join(rootDir, 'assets', 'icon.png');
const icoPath = path.join(rootDir, 'assets', 'icon.ico');
const icoSizes = [16, 24, 32, 48, 64, 128, 256];

app.disableHardwareAcceleration();

function pngDimensions(buffer) {
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20)
  };
}

function resizePng(buffer, size) {
  const png = nativeImage.createFromBuffer(buffer).resize({
    width: size,
    height: size,
    quality: 'best'
  }).toPNG();
  const dimensions = pngDimensions(png);
  if (dimensions.width !== size || dimensions.height !== size) {
    throw new Error(`Expected ${size}x${size}, got ${dimensions.width}x${dimensions.height}`);
  }

  return png;
}

async function renderPng(svgUrl, size) {
  const window = new BrowserWindow({
    show: false,
    frame: false,
    transparent: true,
    resizable: false,
    width: size,
    height: size,
    backgroundColor: '#00000000',
    webPreferences: {
      offscreen: true,
      backgroundThrottling: false,
      webSecurity: false
    }
  });

  const html = `
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    html, body {
      width: ${size}px;
      height: ${size}px;
      margin: 0;
      overflow: hidden;
      background: transparent;
    }

    img {
      width: ${size}px;
      height: ${size}px;
      display: block;
    }
  </style>
</head>
<body>
  <img src="${svgUrl}" alt="">
</body>
</html>`;

  await window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
  await new Promise((resolve) => setTimeout(resolve, 100));

  const capture = await window.webContents.capturePage({
    x: 0,
    y: 0,
    width: size,
    height: size
  });
  window.destroy();

  const exact = capture.resize({
    width: size,
    height: size,
    quality: 'best'
  });

  const png = exact.toPNG();
  const dimensions = pngDimensions(png);
  if (dimensions.width !== size || dimensions.height !== size) {
    throw new Error(`Expected ${size}x${size}, got ${dimensions.width}x${dimensions.height}`);
  }

  return png;
}

function makeIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);

  const directory = Buffer.alloc(entries.length * 16);
  let offset = header.length + directory.length;

  entries.forEach((entry, index) => {
    const base = index * 16;
    directory.writeUInt8(entry.size === 256 ? 0 : entry.size, base);
    directory.writeUInt8(entry.size === 256 ? 0 : entry.size, base + 1);
    directory.writeUInt8(0, base + 2);
    directory.writeUInt8(0, base + 3);
    directory.writeUInt16LE(1, base + 4);
    directory.writeUInt16LE(32, base + 6);
    directory.writeUInt32LE(entry.png.length, base + 8);
    directory.writeUInt32LE(offset, base + 12);
    offset += entry.png.length;
  });

  return Buffer.concat([header, directory, ...entries.map((entry) => entry.png)]);
}

app.whenReady().then(async () => {
  const svgUrl = pathToFileURL(svgPath).href;

  const png512 = await renderPng(svgUrl, 512);
  fs.writeFileSync(pngPath, png512);

  const icoEntries = icoSizes.map((size) => ({
    size,
    png: resizePng(png512, size)
  }));
  fs.writeFileSync(icoPath, makeIco(icoEntries));

  console.log(`Wrote ${path.relative(rootDir, pngPath)}`);
  console.log(`Wrote ${path.relative(rootDir, icoPath)}`);
  app.quit();
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
  app.quit();
});
