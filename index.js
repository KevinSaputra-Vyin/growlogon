const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const rateLimiter = require('express-rate-limit');
const compression = require('compression');

app.use(compression({
    level: 5,
    threshold: 0,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));
app.set('view engine', 'ejs');
app.set('trust proxy', 1);
app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', '*');
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept',
    );
    console.log(`[${new Date().toLocaleString()}] ${req.method} ${req.url} - ${res.statusCode}`);
    next();
});
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(rateLimiter({ windowMs: 15 * 60 * 1000, max: 100, headers: true }));

app.all('/player/login/dashboard', function (req, res) {
    const tData = {};
    try {
        const uData = JSON.stringify(req.body).split('"')[1].split('\\n'); const uName = uData[0].split('|'); const uPass = uData[1].split('|');
        for (let i = 0; i < uData.length - 1; i++) { const d = uData[i].split('|'); tData[d[0]] = d[1]; }
        if (uName[1] && uPass[1]) { res.redirect('/player/growid/login/validate'); }
    } catch (why) { console.log(`Warning: ${why}`); }

    res.render(__dirname + '/public/html/dashboard.ejs', { data: tData });
});

app.all('/player/growid/login/validate', (req, res) => {
    const _token = req.body._token;
    const growId = req.body.growId;
    const password = req.body.password;

    const token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}`,
    ).toString('base64');

    res.send(
        `{"status":"success","message":"Account Validated.","token":"${token}","url":"","accountType":"growtopia"}`,
    );
});

// Add this right before the '/player/*' route handler

app.all('/player/growid/register/validate', (req, res) => {
    const { growId, password, verifyPassword, email } = req.body;
    
    // Simple validation
    if (!growId || !password || !verifyPassword || !email) {
        return res.send(
            `{"status":"error","message":"All fields are required"}`
        );
    }

    if (growId.length < 8) {
        return res.send(
            `{"status":"error","message":"GrowID must be at least 8 characters"}`
        );
    }

    if (password.length < 8) {
        return res.send(
            `{"status":"error","message":"Password must be at least 8 characters"}`
        );
    }

    if (password !== verifyPassword) {
        return res.send(
            `{"status":"error","message":"Passwords do not match"}`
        );
    }

    if (!email.includes('@') || !email.includes('.')) {
        return res.send(
            `{"status":"error","message":"Invalid email address"}`
        );
    }

    // Generate token (same format as login)
    const _token = Date.now().toString(); // Simple token generation
    const token = Buffer.from(
        `_token=${_token}&register_growId=${growId}&register_password=${password}&register_email=${email}`,
    ).toString('base64');

    // Success response (matches login format)
    res.send(
        `{"status":"success","message":"Account Created.","token":"${token}","url":"","accountType":"growtopia"}`
    );
});

// Keep all your existing routes below...

app.all('/player/*', function (req, res) {
    res.status(301).redirect('https://api.yoruakio.tech/player/' + req.path.slice(8));
});

app.get('/', function (req, res) {
    res.send('Hello World!');
});

app.listen(5000, function () {
    console.log('Listening on port 5000');
});
