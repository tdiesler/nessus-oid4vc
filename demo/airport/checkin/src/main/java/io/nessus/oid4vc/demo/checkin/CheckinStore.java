package io.nessus.oid4vc.demo.checkin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CheckinStore {

    private final Map<String, BoardingPass> boardingPasses = new ConcurrentHashMap<>();

    public BoardingPass getBoardingPass(String credentialId) {
        return boardingPasses.get(credentialId);
    }

    public Map<String, BoardingPass> getAllBoardingPasses() {
        return Map.copyOf(boardingPasses);
    }

    public void putBoardingPass(String credentialId, BoardingPass boardingPass) {
        boardingPasses.put(credentialId, boardingPass);
    }

    public void clear() {
        boardingPasses.clear();
    }
}
