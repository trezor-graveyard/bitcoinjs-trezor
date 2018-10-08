module.exports = {
    rootDir: './src',
    automock: false,
    coverageDirectory: '../coverage/',
    collectCoverage: true,
    testURL: 'http://localhost',
    modulePathIgnorePatterns: [
        'node_modules',
    ],
    collectCoverageFrom: [
        '**.js',
    ],
};
