package com.nabil.cryptography.controller;

import com.nabil.cryptography.service.CryptographyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.nio.file.Files;
import java.util.Base64;
import java.util.HashMap;

@Controller
public class MainController {

    @Autowired
    private CryptographyService cryptographyService;

    @Value("${passPhrase}") //Ngambil password dari application.properties
    private String passPhrase;

    @GetMapping("/") //membaca homesweethome.html sebagai homepage
    private String HomeSweetHome() {
        return "homesweethome";
    }

    @PostMapping("/encryptThisText")
    private String encryptText(Model model, @RequestParam HashMap<String, String> form) {
        String encryptTextValue = form.get("encryptText");
        try {
            File publicKeyFile = ResourceUtils.getFile("classpath:publicKeyNabil.asc"); //Ambil Public Key dari resources
            byte[] publicKeyByte = Files.readAllBytes(publicKeyFile.toPath()); // Convert Public Key ke byte
            String publicKeyString = new String(publicKeyByte); // Convert lagi ke String untuk mengambil isi dari file
            byte[] encrypted = cryptographyService.encrypt(encryptTextValue.getBytes(), publicKeyString); //Enkrip teks dalam bentuk byte
            String encryptedText = Base64.getEncoder().encodeToString(encrypted); //konvert teks yang telah di enkrip byte ke base64
            model.addAttribute("encryptedText", encryptedText); //di lempar ke html
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "homesweethome";
    }

    @PostMapping("/decryptThisText")
    private String decryptText(Model model, @RequestParam HashMap<String, String> form) {
        String decryptTextValue = form.get("decryptText"); //Ngamil value(text yang telah di enkrip) dari textarea
        try {
            File privateKeyFile = ResourceUtils.getFile("classpath:privateKeyNabil.asc"); // Ambil private key
            byte[] privateKeyByte = Files.readAllBytes(privateKeyFile.toPath()); // Private key diubah ke byte
            String privateKeyString = new String(privateKeyByte); //Private key byte ke string untuk mendapatkan isinya
            byte[] decodedBytes = Base64.getDecoder().decode(decryptTextValue); // Base64 ke byte
            byte[] decrypted = cryptographyService.decrypt(decodedBytes, privateKeyString, passPhrase); //Dekrip teks ke byte
            String decryptedText = new String(decrypted); //hasil dari dekrip teks dalam bentuk String
            model.addAttribute("decryptedText", decryptedText); //hasil dekrip teks string di lempar ke html
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "homesweethome";
    }

    @PostMapping("/encryptThisFile")
    @ResponseBody
    private String encryptFile(HttpSession session, HttpServletResponse response, @RequestPart("file") MultipartFile fileUploaded) {
        try {
            String pathLocation = File.separator + "encrypt"; //Lokasi temp file
            String tomcatLocationTemp = session.getServletContext().getRealPath(pathLocation); //Lokasi tomcat temp

            File destinationFolder = new File(tomcatLocationTemp + File.separator);
            if (!destinationFolder.exists()) {
                destinationFolder.mkdirs(); //Buat folder temp
            }
            System.out.println("Tomcat Location : " + tomcatLocationTemp);
            File locationUploadedFileTemp = new File(tomcatLocationTemp + File.separator + fileUploaded.getOriginalFilename()); //Supaya file yang telah di upload mempunyai directory
            fileUploaded.transferTo(locationUploadedFileTemp); //File yang telah di upload di transfer ke lokasi temp
            String chiperFilePath = locationUploadedFileTemp + ".gpg"; //File yang akan di enkrip dengan ekstensi .gpg
            File fileChiper = new File(chiperFilePath);
            File publicKeyFile = ResourceUtils.getFile("classpath:publicKeyNabil.asc"); //Ambil public key
            byte[] publicKeyByte = Files.readAllBytes(publicKeyFile.toPath()); //Public Key File ke byte
            String publicKeyString = new String(publicKeyByte); //Public Key byte ke String
            cryptographyService.encrypt(locationUploadedFileTemp, fileChiper, publicKeyString); //Enkrip

            //Sesi download
            response.setContentType("application/pgp-encrypted");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + fileChiper.getName() + "\"");
            ServletOutputStream sos = response.getOutputStream();
            sos.write(Files.readAllBytes(fileChiper.toPath()));
            sos.flush();
            sos.close();
            //Sesi download

            if (locationUploadedFileTemp != null && fileChiper != null) { //File temp dihapus semua
                Files.delete(locationUploadedFileTemp.toPath());
                Files.delete(fileChiper.toPath());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "homesweethome";
    }

    @PostMapping("decryptThisFile")
    @ResponseBody
    private String decryptFile(HttpSession session, HttpServletResponse response, @RequestPart("file") MultipartFile fileUploaded) {
        try {
            String pathLocation = File.separator + "decrypt"; //Lokasi temp file
            String tomcatLocationTemp = session.getServletContext().getRealPath(pathLocation); //Lokasi tomcat temp

            File destinationFolder = new File(tomcatLocationTemp + File.separator);
            if (!destinationFolder.exists()) {
                destinationFolder.mkdirs(); //Buat folder temp
            }
            System.out.println("Tomcat Location : " + tomcatLocationTemp);
            File locationUploadedFileTemp = new File(tomcatLocationTemp + File.separator + fileUploaded.getOriginalFilename()); //Supaya file yang telah di upload mempunyai directory
            fileUploaded.transferTo(locationUploadedFileTemp); //File yang telah di upload di transfer ke lokasi temp
            String chiperFilePath = locationUploadedFileTemp.getPath(); //File yang akan di dekrip dengan ekstensi .gpg
            File fileChiper = new File(chiperFilePath);
            File privateKeyFile = ResourceUtils.getFile("classpath:privateKeyNabil.asc"); // Ambil private key
            byte[] privateKeyByte = Files.readAllBytes(privateKeyFile.toPath()); // Private key diubah ke byte
            String privateKeyString = new String(privateKeyByte); //Private key byte ke string untuk mendapatkan isinya
            cryptographyService.decrypt(fileChiper, locationUploadedFileTemp, privateKeyString, passPhrase);

            //Sesi download
            response.setContentType("application/json");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + fileChiper.getName() + "\"");
            ServletOutputStream sos = response.getOutputStream();
            sos.write(Files.readAllBytes(fileChiper.toPath()));
            sos.flush();
            sos.close();
            //Sesi download

            if (locationUploadedFileTemp != null && fileChiper != null) { //File temp dihapus semua
                Files.delete(locationUploadedFileTemp.toPath());
                Files.delete(fileChiper.toPath());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "homesweethome";
    }
}
