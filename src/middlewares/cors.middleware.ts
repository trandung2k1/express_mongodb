import cors from 'cors';
const whitelist: string[] = ['http://localhost:5500', 'http://localhost:5173'];
const corsOptions: cors.CorsOptions = {
    origin: (
        requestOrigin: string | undefined,
        callback: (
            err: Error | null,
            origin?: boolean | string | RegExp | (boolean | string | RegExp)[],
        ) => void,
    ): void => {
        if (requestOrigin) {
            if (whitelist.indexOf(requestOrigin) !== -1) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        }
    },
    credentials: true,
};
export default corsOptions;
