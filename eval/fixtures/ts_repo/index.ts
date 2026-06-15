import express from 'express';

const app = express();

function handleRoute(req: any, res: any) {
    res.send('Hello');
}

app.get('/', handleRoute);
export default app;
