package ru.pobopo.schelkovo.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SpotStatus {
    private SpotStatusType state;
    private String comment = "";
}
