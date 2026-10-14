-- MySQL dump 10.13  Distrib 8.0.45, for Win64 (x86_64)
--
-- Host: localhost    Database: cis_db
-- ------------------------------------------------------
-- Server version	8.0.45

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `cis_commands`
--

DROP TABLE IF EXISTS `cis_commands`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cis_commands` (
  `command_id` int NOT NULL AUTO_INCREMENT,
  `rule_id` int NOT NULL,
  `command_type` varchar(20) NOT NULL,
  `step_order` int NOT NULL DEFAULT '1',
  `command` text NOT NULL,
  `description` text,
  `expected_result` text,
  `match_type` varchar(20) DEFAULT NULL,
  `timeout_seconds` int NOT NULL DEFAULT '30',
  `requires_root` tinyint(1) NOT NULL DEFAULT '0',
  `shell` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`command_id`),
  KEY `idx_rule_type_step` (`rule_id`,`command_type`,`step_order`),
  CONSTRAINT `fk_commands_rule` FOREIGN KEY (`rule_id`) REFERENCES `cis_rules` (`rule_id`) ON DELETE CASCADE,
  CONSTRAINT `chk_command_type` CHECK ((`command_type` in (_utf8mb4'AUDIT',_utf8mb4'REMEDIATION',_utf8mb4'VERIFY'))),
  CONSTRAINT `chk_match_type` CHECK (((`match_type` is null) or (`match_type` in (_utf8mb4'EXACT',_utf8mb4'CONTAINS',_utf8mb4'NOT_CONTAINS',_utf8mb4'REGEX',_utf8mb4'EXIT_CODE',_utf8mb4'NO_OUTPUT'))))
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cis_commands`
--

LOCK TABLES `cis_commands` WRITE;
/*!40000 ALTER TABLE `cis_commands` DISABLE KEYS */;
INSERT INTO `cis_commands` VALUES (7,2,'AUDIT',1,'dpkg-query -W -f=\'${db:Status-Status} ${Package}\\n\' sudo-rs sudo 2>/dev/null | awk \'$1==\"installed\"{print $2}\'','Verify that one of sudo-rs or sudo is installed.',NULL,'CONTAINS',30,0,'bash','2026-09-30 18:44:00','2026-09-30 18:44:00'),(8,3,'AUDIT',1,'/usr/sbin/apparmor_status | grep profiles','Verify that all loaded AppArmor profiles are in enforce mode and that other modes contain zero profiles.',NULL,'CONTAINS',30,0,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(9,4,'AUDIT',1,'dpkg-query -s ufw &>/dev/null && echo \"ufw is installed\"','Verify that Uncomplicated Firewall (UFW) is installed.','ufw is installed','CONTAINS',30,0,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(10,4,'REMEDIATION',1,'apt install ufw','Install Uncomplicated Firewall (UFW).',NULL,NULL,60,1,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(11,5,'AUDIT',1,'systemctl is-enabled ufw.service','Verify that ufw.service is enabled.','enabled','EXACT',30,0,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(12,5,'AUDIT',2,'systemctl is-active ufw.service','Verify that ufw.service is active.','active','EXACT',30,0,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(13,5,'AUDIT',3,'ufw status','Verify that UFW is active.','Status: active','CONTAINS',30,0,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(14,5,'REMEDIATION',1,'systemctl unmask ufw.service','Unmask the ufw.service.',NULL,NULL,30,1,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(15,5,'REMEDIATION',2,'systemctl --now enable ufw.service','Enable and start the ufw.service.',NULL,NULL,30,1,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(16,5,'REMEDIATION',3,'ufw enable','Enable UFW.',NULL,NULL,30,1,'bash','2026-09-30 18:48:25','2026-09-30 18:48:25'),(17,1,'AUDIT',1,'grep \"^\\s*linux\" /boot/grub/grub.cfg | grep \"apparmor=0\"','Verify that AppArmor has not been disabled at the kernel command line.',NULL,'NO_OUTPUT',30,0,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(18,1,'AUDIT',2,'grep \"apparmor=0\" /etc/default/grub.d/apparmor.cfg 2>/dev/null','Verify that AppArmor has not been disabled in the AppArmor GRUB configuration.',NULL,'NO_OUTPUT',30,0,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(19,1,'AUDIT',3,'systemctl is-enabled apparmor.service 2>/dev/null','Verify that the AppArmor service is enabled.','enabled','EXACT',30,0,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(20,1,'AUDIT',4,'systemctl is-active apparmor.service 2>/dev/null','Verify that the AppArmor service is active.','active','EXACT',30,0,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(21,1,'AUDIT',5,'/usr/sbin/apparmor_status 2>/dev/null | grep \'profiles are loaded\'','Verify that AppArmor profiles are loaded.','profiles are loaded','CONTAINS',30,0,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(22,1,'REMEDIATION',1,'update-grub','Update the GRUB configuration after removing the apparmor=0 parameter.',NULL,NULL,30,1,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15'),(23,1,'REMEDIATION',2,'reboot','Reboot the system after updating the GRUB configuration.',NULL,NULL,60,1,'bash','2026-09-30 18:51:15','2026-09-30 18:51:15');
/*!40000 ALTER TABLE `cis_commands` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cis_rules`
--

DROP TABLE IF EXISTS `cis_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cis_rules` (
  `rule_id` int NOT NULL AUTO_INCREMENT,
  `cis_id` varchar(20) NOT NULL,
  `title` varchar(255) NOT NULL,
  `description` text,
  `platform` varchar(50) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `is_active` tinyint(1) NOT NULL DEFAULT '1',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`rule_id`),
  UNIQUE KEY `uq_cis_rule` (`cis_id`,`platform`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cis_rules`
--

LOCK TABLES `cis_rules` WRITE;
/*!40000 ALTER TABLE `cis_rules` DISABLE KEYS */;
INSERT INTO `cis_rules` VALUES (1,'1.3.1.2','Ensure AppArmor is enabled','AppArmor is a kernel enhancement to confine programs to a limited set of resources.','Ubuntu','2026-09-30 18:40:21',1,'2026-09-30 18:40:21'),(2,'5.2.1','Ensure sudo is installed','sudo allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.','Ubuntu','2026-09-30 18:44:00',1,'2026-09-30 18:44:00'),(3,'1.3.1.3','Ensure all AppArmor Profiles are enforcing','AppArmor profiles define what resources applications are able to access.','Ubuntu','2026-09-30 18:48:25',1,'2026-09-30 18:48:25'),(4,'4.1.1','Ensure ufw is installed','The Uncomplicated Firewall (ufw) is a frontend for iptables and is particularly well-suited for host-based firewalls.','Ubuntu','2026-09-30 18:48:25',1,'2026-09-30 18:48:25'),(5,'4.1.2','Ensure ufw service is configured','The ufw.service manages UFW and is responsible for applying and maintaining firewall rules.','Ubuntu','2026-09-30 18:48:25',1,'2026-09-30 18:48:25');
/*!40000 ALTER TABLE `cis_rules` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-01  2:53:46
