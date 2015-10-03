/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package demosm2;

import com.axis.security.ByteArrayWrapper;
import com.axis.security.ECKeyPair;
import com.axis.security.ECPoint;
import com.axis.security.FpPoint;
import com.axis.security.SM2;
import com.axis.security.SM2KeyExchangeInformation;
import com.axis.security.SM3;
import com.axis.security.Utils;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.util.Arrays;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.TextField;

/**
 *
 * @author Splash
 */
public class FXMLDocumentController implements Initializable {
    
    @FXML
    private TextField textFieldMessage;
    
    @FXML
    private TextField textFieldPrivateKey;
    
    @FXML
    private TextField textFieldPublicKeyX;
    
    @FXML
    private TextField textFieldPublicKeyY;
    
    @FXML
    private TextField textFieldC1X1;
    
    @FXML
    private TextField textFieldC1Y1;
    
    @FXML
    private TextField textFieldC2;
    
    @FXML
    private TextField textFieldC3;
    
    @FXML
    private TextField textFieldPlainText;
    
    // ---------------------------------------
    @FXML
    private TextField textFieldDSAMessage;
    
    @FXML
    private TextField textFieldDSAUserId;
    
    @FXML
    private TextField textFieldDSAPrivateKey;
    
    @FXML
    private TextField textFieldDSAPublicKeyX;
    
    @FXML
    private TextField textFieldDSAPublicKeyY;
    
    @FXML
    private TextField textFieldDSAr;
    
    @FXML
    private TextField textFieldDSAs;
    
    @FXML
    private TextField textFieldDSAStatus;  
    
     // ---------------------------------------
    @FXML
    private TextField textFieldEXA;
    
    @FXML
    private TextField textFieldEXB;
    
    @FXML
    private TextField textFieldEXPrivateKeyA;
    
    @FXML
    private TextField textFieldEXPrivateKeyB;
    
    @FXML
    private TextField textFieldEXPublicKeyXA;
    
    @FXML
    private TextField textFieldEXPublicKeyXB;
    
    @FXML
    private TextField textFieldEXPublicKeyYA;
    
    @FXML
    private TextField textFieldEXPublicKeyYB;
    
    @FXML
    private TextField textFieldS1A;
    
    @FXML
    private TextField textFieldS1B;
    
    @FXML
    private TextField textFieldS2A;
    
    @FXML
    private TextField textFieldS2B;
    
    @FXML
    private TextField textFieldShareKeyA;  
    
    @FXML
    private TextField textFieldShareKeyB; 
    
    @FXML
    private TextField textFieldEXStatus; 
    
    @FXML
    private void handleButtonCipher(ActionEvent event) throws UnsupportedEncodingException, IOException {
        // 显示消息
        String msg = textFieldMessage.getText();
        if(msg.isEmpty()) return;
        byte[] data = msg.getBytes("UTF-8");
        
        // 显示密钥
        try (SM2 sm2 = SM2.CreateInstance(521))
        {
            ECKeyPair keyPair = sm2.GetKeyPair();         
            
            BigInteger PrivateKey = keyPair.PrivateKey;
            ECPoint PublicKey = keyPair.PublicKey;

            textFieldPrivateKey.setText(Utils.ToString(sm2.GetEncoded(PrivateKey)));
            textFieldPublicKeyX.setText(Utils.ToString(sm2.GetEncoded(PublicKey.getX())));
            textFieldPublicKeyY.setText(Utils.ToString(sm2.GetEncoded(PublicKey.getY())));

            // 显示加密
            byte[] CipherText = sm2.EncryptValue(data, PublicKey);

            BigInteger X1 = new BigInteger(1, Arrays.copyOfRange(CipherText, 0, sm2.mFieldSizeInBytes));
            BigInteger Y1 = new BigInteger(1, Arrays.copyOfRange(CipherText, sm2.mFieldSizeInBytes, sm2.mFieldSizeInBytes << 1));
            ECPoint C1 = new FpPoint(sm2.mCurve, sm2.mCurve.FromBigInteger(X1), sm2.mCurve.FromBigInteger(Y1));
            byte[] C2 = new byte[data.length];
            System.arraycopy(CipherText, sm2.mFieldSizeInBytes << 1, C2, 0, data.length);
            byte[] C3 = new byte[SM3.HashSizeInBytes];
            System.arraycopy(CipherText, (sm2.mFieldSizeInBytes << 1) + data.length, C3, 0, SM3.HashSizeInBytes);

            textFieldC1X1.setText(Utils.ToString(sm2.GetEncoded(C1.getX())));
            textFieldC1Y1.setText(Utils.ToString(sm2.GetEncoded(C1.getY())));
            textFieldC2.setText(Utils.ToString(C2));
            textFieldC3.setText(Utils.ToString(C3));

            // 解密过程
            byte[] PlainText = sm2.DecryptValue(CipherText, PrivateKey);
            if (PlainText != null)
            {
                textFieldPlainText.setText(new String(PlainText, "UTF-8"));
            }
            else
            {    
                textFieldPlainText.clear();
            }
        }
    }
    
    @FXML
    private void handleButtonDSA(ActionEvent event) throws UnsupportedEncodingException, IOException {
        if (textFieldDSAMessage.getText().isEmpty() || textFieldDSAUserId.getText().isEmpty()) return;        
        // 显示消息
        String msg = textFieldDSAMessage.getText();
        byte[] data = msg.getBytes("UTF-8");
        byte[] UserId = textFieldDSAUserId.getText().getBytes("UTF-8");
        try (SM2 sm2 = new SM2())
        {
            ECKeyPair keyPair = sm2.GetKeyPair();         
            
            BigInteger PrivateKey = keyPair.PrivateKey;
            ECPoint PublicKey = keyPair.PublicKey;

            textFieldDSAPrivateKey.setText(Utils.ToString(sm2.GetEncoded(PrivateKey)));
            textFieldDSAPublicKeyX.setText(Utils.ToString(sm2.GetEncoded(PublicKey.getX())));
            textFieldDSAPublicKeyY.setText(Utils.ToString(sm2.GetEncoded(PublicKey.getY())));

            byte[] Signature = sm2.SignData(data, UserId, PrivateKey);
            textFieldDSAr.setText(Utils.ToString(Signature, 0, sm2.mFieldSizeInBytes));
            textFieldDSAs.setText(Utils.ToString(Signature, sm2.mFieldSizeInBytes, sm2.mFieldSizeInBytes));

            if (sm2.VerifyData(data, UserId, PublicKey, Signature))
                textFieldDSAStatus.setText("签名有效");
            else
                textFieldDSAStatus.setText("失败！！！");
        }
    }
    
    @FXML
    private void handleButtonKeyExchange(ActionEvent event) throws UnsupportedEncodingException, IOException {
        try (SM2 sm2 = new SM2())
        {
            SM2KeyExchangeInformation InformationA = new SM2KeyExchangeInformation();
            ECKeyPair KeyPairA = sm2.GetKeyPair();
            InformationA.PrivateKey = KeyPairA.PrivateKey;
            InformationA.PublicKey = KeyPairA.PublicKey;

            ECKeyPair KeyPairAR = sm2.GetKeyPair();
            InformationA.r = KeyPairAR.PrivateKey;
            InformationA.R = KeyPairAR.PublicKey;

            SM2KeyExchangeInformation InformationB = new SM2KeyExchangeInformation();
            ECKeyPair KeyPairB = sm2.GetKeyPair();
            InformationB.PrivateKey = KeyPairB.PrivateKey;
            InformationB.PublicKey = KeyPairB.PublicKey;

            ECKeyPair KeyPairBR = sm2.GetKeyPair();
            InformationB.r = KeyPairBR.PrivateKey;
            InformationB.R = KeyPairBR.PublicKey;

            InformationA.Z = sm2.ComputeZ(textFieldEXA.getText().getBytes("UTF-8"), InformationA.PublicKey);
            InformationB.Z = sm2.ComputeZ(textFieldEXB.getText().getBytes("UTF-8"), InformationB.PublicKey);                

            // 第一次A->B传送的信息
            InformationB.PartnerPublicKey = InformationA.PublicKey;                
            InformationB.PartnerR = InformationA.R;
            InformationB.PartnerZ = InformationA.Z;
            ByteArrayWrapper SharedKeyB = new ByteArrayWrapper();
            if(sm2.KeyAgreement(InformationB, false, SM3.HashSizeInBytes, SharedKeyB, true))
            {   // 第一次B->A传送的信息
                InformationA.PartnerPublicKey = InformationB.PublicKey;
                InformationA.PartnerR = InformationB.R;
                InformationA.PartnerZ = InformationB.Z;                    
                InformationA.PartnerS = InformationB.S1;

                ByteArrayWrapper SharedKeyA = new ByteArrayWrapper();
                if (sm2.KeyAgreement(InformationA, true, SM3.HashSizeInBytes, SharedKeyA, true) && sm2.KeyConfirm(InformationA, true))
                {   // 第二次A->B传送的信息
                    InformationB.PartnerS = InformationA.S2;
                    if (sm2.KeyConfirm(InformationB, false))
                    {   // 密钥协商成功
                        textFieldEXStatus.setText("密钥交换成功！");
                        textFieldEXPrivateKeyA.setText(Utils.ToString(sm2.GetEncoded(InformationA.PrivateKey)));
                        textFieldEXPublicKeyXA.setText(Utils.ToString(sm2.GetEncoded(InformationA.PublicKey.getX())));
                        textFieldEXPublicKeyYA.setText(Utils.ToString(sm2.GetEncoded(InformationA.PublicKey.getY())));
                        textFieldS1A.setText(Utils.ToString(InformationA.S1));
                        textFieldS2A.setText(Utils.ToString(InformationA.S2));
                        textFieldShareKeyA.setText(Utils.ToString(SharedKeyA.data));

                        textFieldEXPrivateKeyB.setText(Utils.ToString(sm2.GetEncoded(InformationB.PrivateKey)));
                        textFieldEXPublicKeyXB.setText(Utils.ToString(sm2.GetEncoded(InformationB.PublicKey.getX())));
                        textFieldEXPublicKeyYB.setText(Utils.ToString(sm2.GetEncoded(InformationB.PublicKey.getY())));
                        textFieldS1B.setText(Utils.ToString(InformationB.S1));
                        textFieldS2B.setText(Utils.ToString(InformationB.S2));
                        textFieldShareKeyB.setText(Utils.ToString(SharedKeyB.data));

                        return;
                    }
                }
            }

            textFieldEXStatus.setText("失败！！！");
        }
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        textFieldPrivateKey.setEditable(false);
        textFieldPublicKeyX.setEditable(false);
        textFieldPublicKeyY.setEditable(false);
        textFieldC1X1.setEditable(false);
        textFieldC1Y1.setEditable(false);
        textFieldC2.setEditable(false);
        textFieldC3.setEditable(false);
        textFieldPlainText.setEditable(false);
        
        textFieldDSAPrivateKey.setEditable(false);
        textFieldDSAPublicKeyX.setEditable(false);
        textFieldDSAPublicKeyY.setEditable(false);
        textFieldDSAr.setEditable(false);
        textFieldDSAs.setEditable(false);
        textFieldDSAStatus.setEditable(false);     
        
        textFieldEXPrivateKeyA.setEditable(false);
        textFieldEXPrivateKeyB.setEditable(false);
        textFieldEXPublicKeyXA.setEditable(false);
        textFieldEXPublicKeyXB.setEditable(false);
        textFieldEXPublicKeyYA.setEditable(false);
        textFieldEXPublicKeyYB.setEditable(false);         
        textFieldS1A.setEditable(false);
        textFieldS1B.setEditable(false);
        textFieldS2A.setEditable(false);
        textFieldS2B.setEditable(false);
        textFieldShareKeyA.setEditable(false);
        textFieldShareKeyB.setEditable(false); 
        textFieldEXStatus.setEditable(false);     
    }        
}
