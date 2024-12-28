import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;

import java.time.Duration;
import java.util.Collections;
import java.util.Properties;

public class KafkaSSLConsumer {
    public static void main(String[] args) {
        // Kafka consumer configuration
        Properties props = new Properties();
        
        // Kafka broker connection details
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "your-kafka-broker:9092");
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "ssl-consumer-group");
        
        // SSL Configuration
        props.put("security.protocol", "SSL");
        props.put("ssl.truststore.location", "kafka-client.jks");
        props.put("ssl.truststore.password", "your-truststore-password");
        props.put("ssl.keystore.location", "kafka-client.jks");
        props.put("ssl.keystore.password", "your-keystore-password");
        
        // Deserializer configuration
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        
        // Consumer configuration
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        
        // Create consumer
        Consumer<String, String> consumer = new KafkaConsumer<>(props);
        
        try {
            // Subscribe to specific topic
            consumer.subscribe(Collections.singletonList("your-topic-name"));
            
            // Polling loop
            while (true) {
                ConsumerRecords<String, String> records = consumer.poll(100L); // Use long instead of Duration
                
                records.forEach(record -> {
                    System.out.printf("Received message: Topic = %s, Partition = %d, Key = %s, Value = %s%n", 
                        record.topic(), record.partition(), record.key(), record.value());
                });
            }
        } finally {
            consumer.close(); // Ensure consumer is closed
        }
    }
}
