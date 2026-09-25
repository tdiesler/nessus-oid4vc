package io.nessus.oid4vc.demo.checkin;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CheckinStore {

    private final Map<String, BoardingPass> boardingPasses = new ConcurrentHashMap<>();

    public BoardingPass getBoardingPass(String passengerId) {
        return boardingPasses.get(passengerId);
    }

    public Map<String, BoardingPass> getAllBoardingPasses() {
        return Map.copyOf(boardingPasses);
    }

    public void putBoardingPass(String passengerId, BoardingPass boardingPass) {
        boardingPasses.put(passengerId, boardingPass);
    }

    public void clear() {
        boardingPasses.clear();
    }
}
