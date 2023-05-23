import { Express } from 'express';
const expressLayouts = require('express-ejs-layouts');
const viewEngine = (app: Express) => {
    app.use(expressLayouts);
    app.set('view engine', 'ejs');
    app.use(expressLayouts);
    app.set('layout', './layouts/main');
    app.set('views', './src/views');
};

export default viewEngine;
