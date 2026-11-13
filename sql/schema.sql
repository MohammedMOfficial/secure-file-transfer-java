CREATE DATABASE IF NOT EXISTS zt_ftp;
USE zt_ftp;

CREATE TABLE IF NOT EXISTS Userinfo (
    username       VARCHAR(50) PRIMARY KEY,
    salt           VARCHAR(64)  NOT NULL,
    hashedpassword VARCHAR(256) NOT NULL,
    usertype       ENUM('normal','admin') NOT NULL
);

CREATE TABLE IF NOT EXISTS Sessionkey (
    sessionkey VARCHAR(128) PRIMARY KEY,
    username   VARCHAR(50),
    FOREIGN KEY (username) REFERENCES Userinfo(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS File (
    username VARCHAR(50),
    filename VARCHAR(256),
    PRIMARY KEY (username, filename),
    FOREIGN KEY (username) REFERENCES Userinfo(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Log (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    username  VARCHAR(50),
    operation VARCHAR(255),
    time      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES Userinfo(username) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Block (
    ipaddress VARCHAR(45) PRIMARY KEY,
    time      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
