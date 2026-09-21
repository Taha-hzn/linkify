const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '.env') });

const { createApp } = require('./app/server');

if (require.main === module) {
  const { app } = createApp(path.resolve(__dirname));
  const ports = process.env.PORT ? [Number(process.env.PORT)] : [3000, 3011];

  ports.forEach((port) => {
    app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  });
}

module.exports = { createApp };
