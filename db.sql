CREATE TABLE `users` (
    userID INTEGER PRIMARY KEY AUTO_INCREMENT,
    firstName VARCHAR(255) NOT NULL,
    lastName VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    emailCheckHash VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    modePreference INTEGER(1),
    klasse INTEGER
);

CREATE TABLE tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userID INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expiration DATETIME NOT NULL
);

CREATE TABLE `customLessons` (
    cLessonID INTEGER PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    userID INTEGER NOT NULL
);

CREATE TABLE `customLessonVocabs` (
    cLessonID INTEGER NOT NULL,
    vocabID INTEGER NOT NULL
);

CREATE TABLE `userVocabStats` (
    userID INTEGER NOT NULL,
    vocabID INTEGER NOT NULL,
    failCount INTEGER NOT NULL,
    successCount INTEGER NOT NULL
);

CREATE TABLE `verificationCode` (
    userID INTEGER NOT NULL,
    verificationCode INTEGER NOT NULL,
    expiration DATETIME NOT NULL
);

CREATE TABLE `passwordResets` (
    userID INTEGER NOT NULL,
    resetCode INTEGER NOT NULL,
    expiration DATETIME NOT NULL
);
