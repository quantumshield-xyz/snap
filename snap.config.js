module.exports = {
    server: {
        port: 8000,
    },
    input: './index.js', // 소스 파일 위치
    output: {
        path: 'dist',
        filename: 'bundle.js',
    },
};