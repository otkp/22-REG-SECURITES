package org.epragati.security.eumns;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonValue;

public enum UserType {
    ROLE_ADMIN(1, "ADMIN"), ROLE_DEALER(2, "DEALER"), ROLE_CCO(3, "CCO"), ROLE_CUSTOMER_IND(4, "CUSTOMER_IND"), 
    ROLE_CUSTOMER_CORP(5, "COSTOMER_CORP"), ROLE_MVI(6, "MVI"), ROLE_AO(7, "AO"), 
    ROLE_RTO(8, "RTO"), ROLE_HSRP(9, "HSRP"), ROLE_CARDPRINTING(10, "CARDPRINTING"), ROLE_PAYMENT(11, "PAYMENT"), 
    ROLE_CITIZEN(12, "CITIZEN"), ROLE_BODY_BUILDER(13, "BODY_BUILDER"), ROLE_ONLINE_FINANCER(14, "ONLINE FINANCER"), 
    ROLE_OFFLINE_FINANCER(15, "OFFLINE FINANCER"), ROLE_SELLER(16, "SELLER"), ROLE_BUYER(17, "BUYER"), ROLE_FINANCIER(19, "FINANCIER"),
    ROLE_DTC(20, "DTC"), ROLE_PUC(21, "PUC"),ROLE_ALTERATION_AGENCY(22, "ALTERATION_AGENCY"), ROLE_DRIVING_INSTITUTE(23, "DRIVING_INSTITUTE"),
    ROLE_HAZARDOUS_VEH_TRAIN_INST(24, "HAZARDOUS_VEH_TRAIN_INST"), ROLE_MEDICAL_PRACTITIONER(25, "MEDICAL_PRACTITIONER"), ROLE_EXAMINER(26, "EXAMINER"), ROLE_ONLINE_FINANCER_SUB(27,"ROLE_ONLINE_FINANCER_SUB");

    private static final Map<String, UserType> labelToType = new HashMap<String, UserType>();
    private static final Map<Integer, UserType> valueToUserType = new HashMap<Integer, UserType>();

    static {
        for (UserType userType : UserType.values()) {
            labelToType.put(userType.getLabel(), userType);
        }
        for (UserType userType : EnumSet.allOf(UserType.class)) {
            valueToUserType.put(userType.getValue(), userType);
        }
    }

    private UserType(Integer value, String label) {
        this.value = value;
        this.label = label;
    }

    private Integer value;
    private String label;

    @JsonValue
    public String toValue() {
        return this.label;
    }

    public Integer getValue() {
        return value;
    }

    public String getLabel() {
        return label;
    }

    public static UserType getUserType(String label) {
        return labelToType.get(label);
    }

    public static UserType getUserType(Integer value) {
        return valueToUserType.get(value);
    }
}

