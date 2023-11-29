import idea_cipher.IdeaCipher;
import idea_cipher.IdeaCipherException;

import javax.imageio.ImageIO;
import java.awt.image.*;
import java.io.*;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IdeaCipherException, IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Введите путь к файлу ключа");
        String keyFileName = scanner.nextLine();
        byte[] key;
        try {
            key = readFromInputStreamAsBytes(keyFileName);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Введите путь к файлу, который нужно зашифровать/расшифровать");
        String fileName = scanner.nextLine();
        File file = new File(fileName);
        System.out.println("Введите путь к output файлу");
        String outputFileName = scanner.nextLine();
        boolean encode;
        System.out.println("Зашифровать/расшифровать (e/d)");
        String encodeString = scanner.nextLine();
        encode = encodeString.startsWith("e");
        boolean enableCFB;
        System.out.println("Использовать CFB? (y/n)");
        String enableString = scanner.nextLine();
        enableCFB = enableString.startsWith("y");
        boolean generateCorrupt = false;
        String[] splittedName = fileName.split("\\.");
        String format = splittedName[splittedName.length - 1];
        boolean isImage = format.equals("png") || format.equals("jpg") || format.equals("bmp") || format.equals("jpeg");
        if (encode && isImage) {
            System.out.println("Сгенерировать изображение с ошибкой (y/n)");
            String generateCorruptString = scanner.nextLine();
            generateCorrupt = generateCorruptString.startsWith("y");
        }
        IdeaCipher cipher = new IdeaCipher(key, enableCFB);
        byte[] input;
        if (isImage) {
            BufferedImage image = ImageIO.read(file);
            WritableRaster raster = image.getRaster();
            DataBufferByte data = (DataBufferByte) raster.getDataBuffer();
            byte[] res = data.getData();
            int newLength = res.length;
            if (!encode) {
                while (res[res.length - 1] == 0) {
                    newLength--;
                    byte[] res2 = new byte[newLength];
                    System.arraycopy(res, 0, res2, 0, newLength);
                    res = res2;
                }
            }
            byte[] result = encode ? cipher.encode(res) : cipher.decode(res);
            int length = result.length;
            int cntr = 1;
            if (!encode) cntr = -1;
            if (result.length < (image.getHeight() + cntr * (enableCFB ? 8 / image.getWidth() == 0 ? 1 : 8 / image.getWidth() : 4 / image.getWidth() == 0 ? 1 : 4 / image.getWidth())) * image.getWidth() * 4)
                length = (image.getHeight() + cntr * (enableCFB ? 8 / image.getWidth() == 0 ? 1 : 8 / image.getWidth() : 4 / image.getWidth() == 0 ? 1 : 4 / image.getWidth())) * image.getWidth() * 4;
            byte[] res2 = new byte[length];
            System.arraycopy(result, 0, res2, 0, result.length);
            DataBufferByte a = new DataBufferByte(res2, length);
            Raster rstr = Raster.createRaster(image.getSampleModel().createCompatibleSampleModel(image.getWidth(), image.getHeight() + cntr * (enableCFB ? 8 / image.getWidth() == 0 ? 1 : 8 / image.getWidth() : 4 / image.getWidth() == 0 ? 1 : 4 / image.getWidth())), a, null);
            BufferedImage image1 = new BufferedImage(image.getWidth(), image.getHeight() + cntr * (enableCFB ? 8 / image.getWidth() == 0 ? 1 : 8 / image.getWidth() : 4 / image.getWidth() == 0 ? 1 : 4 / image.getWidth()), image.getType());
            image1.setData(rstr);
            ImageIO.write(image1, format, new File(outputFileName.endsWith("." + format) ? outputFileName : outputFileName + "." + format));
            if (generateCorrupt) {
                image1.setRGB(image1.getWidth() / 2, image1.getHeight() / 2, 0x59A409);
                ImageIO.write(image1, format, new File(outputFileName.split("\\.")[0] + "_corrupt" + (enableCFB ? "_cfb" : "") + "." + format));
            }
        } else {
            try {
                input = readFromInputStreamAsBytes(fileName);
                byte[] result = encode ? cipher.encode(input) : cipher.decode(input);
                writeToOutputStreamAsBytes(outputFileName, result);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static byte[] readFromInputStreamAsBytes(String fileName)
            throws IOException {
        File file = new File(fileName);
        byte[] bytes;
        try (FileInputStream fis = new FileInputStream(file)) {
            bytes = fis.readAllBytes();
        }
        return bytes;
    }

    public static void writeToOutputStreamAsBytes(String fileName, byte[] bytes)
            throws IOException {
        File file = new File(fileName);
        try (FileOutputStream fis = new FileOutputStream(file)) {
            fis.write(bytes);
        }
    }
}